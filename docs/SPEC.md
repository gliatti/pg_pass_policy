# pg_pass_policy — spécification technique (contrat entre les composants)

Ce document est le contrat partagé par tous les développeurs/agents. Toute
modification d'une interface listée ici (table, fonction SQL, GUC, prototype C,
structure partagée) doit être reportée ici **avant** d'être codée.

## 1. Objectif

Extension PostgreSQL (C + SQL) de gestion du cycle de vie des mots de passe des
rôles :

- politique de complexité appliquée à `CREATE ROLE … PASSWORD` et
  `ALTER ROLE … PASSWORD` (hook `check_password_hook`) ;
- historique anti-réutilisation (vérificateurs SCRAM, jamais de clair) ;
- expiration / rotation : durée de vie, période de grâce, alertes,
  `VALID UNTIL` géré automatiquement, rotation avec génération de mot de passe,
  rotation sans coupure par paire de rôles ;
- verrouillage après N échecs d'authentification (hook
  `ClientAuthentication_hook` + mémoire partagée) ;
- background worker intégré pour la maintenance périodique ;
- journal d'audit en table + `ereport(LOG)` + `NOTIFY`.

Références : NIST SP 800-63B (longueur, liste de blocage, pas de rotation
arbitraire pour les humains mais rotation des secrets applicatifs), ANSSI
(recommandations mots de passe 2021 : 12 caractères et 3 classes pour un compte
sensible), CIS PostgreSQL Benchmark (durée de vie, verrouillage), OWASP ASVS v4
chapitre 2.

Versions PostgreSQL cibles : **14, 15, 16, 17, 18**. Développement local sur
16.4 (`pg_config` de pgenv). Chargement obligatoire via
`shared_preload_libraries = 'pg_pass_policy'`, puis `CREATE EXTENSION
pg_pass_policy` dans la base désignée par le GUC `pg_pass_policy.database`
(défaut `postgres`).

## 2. Arborescence

```
Makefile                      PGXS (MODULE_big = pg_pass_policy)
pg_pass_policy.control
sql/pg_pass_policy--1.0.sql   schéma `pass_policy`, tables, fonctions SQL/PLpgSQL, vues, déclarations des fonctions C
src/pg_pass_policy.h          en-tête partagé (contrat C)
src/compat.h                  #ifdef par version
src/pg_pass_policy.c          _PG_init, GUC, chaînage des hooks, shmem request/startup, fonctions utilitaires
src/policy.c                  check_password_hook : complexité, dictionnaire, historique, enregistrement
src/lockout.c                 ClientAuthentication_hook, hash en shmem, fonctions SQL shmem_*
src/worker.c                  background worker (maintenance périodique)
test/sql/*.sql test/expected/*.out   pg_regress
test/shell/*.sh               tests nécessitant de vraies connexions (verrouillage, expiration)
docker/                       matrice 14→18 (docker compose)
cli/                          CLI Rust (clap + sqlx)
web/                          back-office FastAPI + HTMX
docs/                         documentation
```

## 3. Modèle de données (schéma `pass_policy`)

Toutes les tables : `REVOKE ALL ON … FROM PUBLIC`. Lecture possible par le rôle
`pass_policy_viewer` (créé par l'extension, `NOLOGIN`), administration par
superutilisateur ou membre de `pass_policy_admin` (`NOLOGIN`, les fonctions
d'administration sont `SECURITY DEFINER` et vérifient l'appartenance).

### 3.1 `profile` — profils de politique (modèle « le plus abouti », type Oracle)

| colonne | type | défaut | rôle |
|---|---|---|---|
| profile_id | serial PK | | |
| name | text UNIQUE NOT NULL | | `default` créé par l'extension, non supprimable |
| min_length | int | 12 | |
| max_length | int | 128 | |
| min_lower / min_upper / min_digit / min_special | int | 1 / 1 / 1 / 1 | minima par classe (0 = non exigé) |
| min_classes | int | 3 | nombre de classes distinctes exigé (sur 4) |
| reject_username | bool | true | refuse si contient le nom du rôle (insensible à la casse, aussi inversé) |
| reject_dictionary | bool | true | refuse si présent dans `dictionary` (insensible à la casse) |
| reject_prehashed | bool | true | refuse les vérificateurs MD5/SCRAM passés directement (impossible à contrôler) |
| max_repeat | int | 3 | plus de N caractères identiques consécutifs = refus (0 = désactivé) |
| history_count | int | 5 | N derniers mots de passe comparés, l'actuel compris (0 = désactivé) ; DETAIL de `PPP-031` : « from the last N passwords (current one included) » |
| history_days | int | 365 | âge max des entrées comparées |
| max_age | interval NULL | '90 days' | NULL = n'expire jamais |
| min_age | interval | '1 day' | refuse un second changement dans l'intervalle (sauf superutilisateur) |
| grace_period | interval | '7 days' | VALID UNTIL = changed_at + max_age + grace_period |
| warn_before | interval | '14 days' | alerte (audit + NOTIFY) quand expires_at − now() < warn_before |
| max_failures | int | 5 | 0 = verrouillage désactivé |
| failure_window | interval | '15 minutes' | fenêtre de comptage des échecs ; 0 = pas de fenêtre, sinon ≥ 1 s (CHECK) |
| lock_duration | interval NULL | '30 minutes' | NULL = déverrouillage manuel uniquement ; ≥ 1 s (CHECK) |
| created_at / updated_at | timestamptz | now() | |

### 3.2 `role_profile`

`role_oid oid PK, role_name text NOT NULL, profile_id int REFERENCES profile,
assigned_at timestamptz, assigned_by text`. Un rôle sans ligne utilise le profil
`default`. Pas de FK vers `pg_authid` : le worker purge les rôles disparus.

### 3.3 `role_state`

| colonne | type | rôle |
|---|---|---|
| role_oid oid PK, role_name text | | |
| password_changed_at timestamptz | date du dernier changement connu |
| expires_at timestamptz | changed_at + max_age (NULL si pas d'expiration) |
| grace_until timestamptz | expires_at + grace_period |
| last_warned_at timestamptz | dernière alerte envoyée |
| locked_until timestamptz | NULL = non verrouillé, `infinity` = manuel |
| locked_by text | `auto` / `manual` / NULL |
| lock_reason text | |
| must_change bool | forcé par `expire_password()` |
| valid_until_synced timestamptz | dernière valeur écrite dans pg_authid.rolvaliduntil par l'extension |

### 3.4 `password_history`

`id bigserial PK, role_oid oid, role_name text, verifier text NOT NULL,
changed_at timestamptz DEFAULT now()`. `verifier` = contenu de
`pg_authid.rolpassword` (SCRAM-SHA-256). Jamais de clair. Index sur
`(role_oid, changed_at DESC)`.

### 3.5 `dictionary`

`word text PK` (stocké en minuscules), `word_sha256 bytea NOT NULL GENERATED
ALWAYS AS (sha256(decode(replace(word, '\', '\\'), 'escape'))) STORED` + index
unique (SHA-256 des octets bruts du mot dans l'encodage du serveur). L'extension
charge ~200 mots de passe courants (top listes publiques, « password »,
« postgres », « admin », « qwerty », suites de clavier…). Fonction
`load_dictionary(words text[])`.

### 3.6 `audit_log`

`id bigserial PK, event_time timestamptz DEFAULT clock_timestamp(),
event_type text NOT NULL, role_name text, actor text (session_user de
l'appelant, ou 'worker'), database text, client_addr inet, application_name
text, details jsonb`. Index sur `(event_time)`, `(role_name, event_time)`.

`event_type` ∈ { `password_changed`, `password_rejected`, `auth_failed`,
`role_locked`, `role_unlocked`, `expiry_warning`, `password_expired`,
`password_rotated`, `profile_assigned`, `profile_changed`, `pair_switched`,
`valid_until_synced`, `maintenance` }. **Les détails ne contiennent jamais de
mot de passe, ni de vérificateur.**

### 3.7 `rotation_pair` — rotation sans coupure

`pair_name text PK, role_a text, role_b text, group_role text, active_role
text, previous_role text, switched_at timestamptz, previous_valid_until
timestamptz`. Principe : les deux rôles physiques sont membres (avec
`INHERIT`) du rôle de groupe qui porte les privilèges ; `switch_rotation_pair`
génère un mot de passe pour le rôle inactif, le rend actif, et borne le
`VALID UNTIL` de l'ancien à `now() + grace_period` du profil. L'application
récupère le nouveau couple (rôle, mot de passe).

## 4. API SQL (schéma `pass_policy`)

Fonctions PL/pgSQL sauf mention « C ». Les identifiants sont toujours passés
dans `format('%I')` / `quote_ident()` : aucune concaténation brute.

| fonction | retour | note |
|---|---|---|
| `create_profile(name text, VARIADIC settings text[] DEFAULT '{}')` | int | settings = tableau `clé=valeur` ; simpler : `create_profile(name, settings jsonb DEFAULT '{}')` **→ retenu : jsonb** |
| `alter_profile(name text, settings jsonb)` | void | clés = colonnes de `profile` |
| `drop_profile(name text)` | void | refuse `default` et profils assignés |
| `assign_profile(role name, profile text)` | void | audit `profile_assigned`, puis `shmem_reload()` |
| `unassign_profile(role name)` | void | |
| `effective_profile(role name)` | SETOF profile | profil assigné ou `default` |
| `check_password(role text, password text)` | text | **C** — NULL si conforme, sinon le motif de refus (texte en anglais, préfixe stable `PPP-xxx`). Sans effet de bord |
| `generate_password(length int DEFAULT 24, profile text DEFAULT NULL)` | text | **C** — `pg_strong_random`, garanti conforme au profil (classes), alphabet sans caractères ambigus (`0O1lI|`) |
| `rotate_password(role name, length int DEFAULT 24)` | text | génère, `ALTER ROLE … PASSWORD`, `VALID UNTIL`, audit `password_rotated`, NOTIFY ; **retourne le mot de passe une seule fois** ; `SECURITY DEFINER` |
| `expire_password(role name)` | void | `must_change = true`, `VALID UNTIL now()`, audit ; rafraîchit `role_state.role_name` (nom courant) |
| `lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)` | timestamptz | NULL = manuel ; met à jour `role_state` (dont `role_name` = nom courant) + `shmem_lock_role` ; renvoie le `locked_until` posé (`infinity` pour un verrou manuel) |
| `unlock_role(role name)` | void | `role_state` (dont `role_name` = nom courant) + `shmem_unlock_role` + `shmem_reset_failures` |
| `record_password_change(role text, verifier text)` | void | appelée **par le hook C** via SPI après acceptation ; insère l'historique, tronque à `history_count`, met à jour `role_state`, audit `password_changed` |
| `run_maintenance()` | TABLE(action text, role_name text, details jsonb) | ce que fait le worker (appelable par pg_cron) : sync VALID UNTIL, alertes, expirations, déverrouillages auto, purge rôles disparus, réconciliation `pg_authid.rolpassword` vs historique, `shmem_reload()` ; une passe à la fois (`pg_advisory_xact_lock`) |
| `create_rotation_pair(pair text, role_a name, role_b name, group_role name)` | void | crée les rôles manquants (`LOGIN`, membres du groupe) |
| `switch_rotation_pair(pair text, length int DEFAULT 24)` | TABLE(active_role text, password text, previous_role text, previous_valid_until timestamptz) | |
| `purge_audit(older_than interval DEFAULT '365 days')` | bigint | |
| `load_dictionary(words text[])` | int | |
| `audit(event_type text, role_name text, details jsonb DEFAULT '{}')` | void | insère + `pg_notify(current_setting('pg_pass_policy.notify_channel'), json)` ; utilisée par toutes les autres ; `EXECUTE` à `pass_policy_admin` seulement |
| `failed_attempts()` | TABLE(role_name text, failed_count int, first_failure_at timestamptz, last_failure_at timestamptz, locked_until timestamptz) | **C** — lit la shmem |
| `shmem_reload()` | void | **C** — demande, à la validation de la transaction appelante, au worker de recharger les paramètres de verrouillage dans la shmem (un ROLLBACK annule la demande) |
| `shmem_lock_role(role text, until timestamptz)` | void | **C** — `until` NULL = manuel (DT_NOEND) ; écriture shmem différée au COMMIT (annulée par ROLLBACK / ROLLBACK TO SAVEPOINT) |
| `shmem_unlock_role(role text, expired_only boolean DEFAULT false)` | void | **C** — différée au COMMIT ; ne lève pas un verrou automatique posé après la demande ; `expired_only` : ne lève qu'un verrou expiré (étape f de `run_maintenance()`) |
| `shmem_reset_failures(role text)` | void | **C** — différée au COMMIT |
| `worker_status()` | TABLE(pid int, last_run timestamptz, last_reload timestamptz, tracked_roles int) | **C** |

Règles communes à l'API :

- rien n'est accordé à `PUBLIC` (ni `USAGE` sur le schéma, ni `EXECUTE`) : les
  requêtes SPI du hook C tournent en `BOOTSTRAP_SUPERUSERID`
  (`ppp_spi_begin()`), quel que soit l'utilisateur qui change son mot de
  passe. `effective_profile()` est accordée à `pass_policy_viewer` et
  `pass_policy_admin`, `audit()` à `pass_policy_admin`,
  `record_password_change()` à personne. En défense en profondeur,
  `record_password_change()` refuse tout appel hors du hook
  (`pass_policy._in_password_hook()` = false), et `audit()` tout appel hors du
  hook d'un `session_user` qui n'est ni superutilisateur ni membre de
  `pass_policy_admin` : SQLSTATE `42501` (`insufficient_privilege`) ;
- un membre de `pass_policy_admin` qui n'est pas superutilisateur ne peut pas
  viser un rôle **privilégié** avec `rotate_password`, `expire_password`,
  `lock_role`, `unlock_role`, `create_rotation_pair` (rôles de la paire déjà
  existants **et** `group_role` : le `GRANT group_role TO role_a/role_b`
  est exécuté en `SECURITY DEFINER`) ni `switch_rotation_pair`
  (`_require_target_allowed()`, SQLSTATE `42501`). Est privilégié en lui-même
  (`_is_privileged(oid)`, prédicat unique) un rôle qui a `SUPERUSER`,
  `REPLICATION` ou `BYPASSRLS`, un rôle prédéfini `pg_*`
  (`pg_execute_server_program`, `pg_write_server_files`… ; `pg_database_owner`
  est exclu : tout propriétaire de base en est membre implicite et il
  n'apporte rien au-delà de la propriété) ou, sur PostgreSQL ≤ 15, un rôle
  `CREATEROLE`. Une cible est refusée si elle est privilégiée ou membre, même
  indirect, d'un rôle privilégié (`SET ROLE` / `INHERIT` en donnent les
  privilèges) : le même prédicat s'applique à la cible et à chacun de ses
  ancêtres ;
- `assign_profile`, `unassign_profile` et `alter_profile` ne sont **pas**
  soumises à `_require_target_allowed()` : un membre de `pass_policy_admin`
  agit sur tous les rôles LOGIN, superutilisateurs compris, par les profils
  (`default` inclus : expiration, `VALID UNTIL` posé par `run_maintenance()`,
  verrouillage). La seule protection des rôles privilégiés contre ce chemin
  est `pg_pass_policy.exempt_roles` (recommandé : `'postgres'`) ;
- `generate_password(length, profile)` respecte les bornes absolues (8 à 512)
  **et** `min_length` / `max_length` du profil (`default` si NULL) : avec le
  profil `default` (`min_length = 12`), `generate_password(8)` échoue
  (`22023`, « password length 8 does not comply with profile "default" ») ;
  `rotate_password(role, length)` est soumise à la même règle via le profil
  effectif du rôle.

Vues :

- `v_role_status(role_name, profile, password_changed_at, expires_at,
  grace_until, days_left, locked_until, failed_count, status, role_oid)` avec
  `status` ∈ `ok | warning | grace | expired | locked | never_expires |
  unknown` ; `unknown` = date de changement inconnue (rôle antérieur à
  l'extension) ; `role_oid` (dernière colonne) sert de clé de jointure avec
  `role_state`, dont `role_name` peut garder l'ancien nom après
  `ALTER ROLE … RENAME` ;
- `v_expiring` : status in (warning, grace, expired) ;
- `v_locked(role_name, locked_until, locked_by, lock_reason, failed_count)` :
  `role_state` joint par OID ;
- `v_recent_audit` : 1000 derniers événements.

Message JSON de `NOTIFY` : `{"event":"…","role":"…","at":"…","details":{…}}`.

## 5. GUC (tous préfixés `pass_policy.`)

| nom | type | défaut | contexte | rôle |
|---|---|---|---|---|
| enabled | bool | on | SIGHUP | désactive hooks (le worker tourne mais ne modifie rien) |
| database | string | postgres | postmaster | base où est installée l'extension / où se connecte le worker |
| worker_interval | int (s) | 60 | SIGHUP | 0 = worker désactivé (appel manuel `run_maintenance`) |
| max_tracked_roles | int | 1024 | postmaster | taille du hash shmem |
| manage_valid_until | bool | on | SIGHUP | le worker écrit `rolvaliduntil` ; à `off`, `run_maintenance()` relève tout de même (mode `unblock`) un `VALID UNTIL` passé qu'elle a elle-même posé (`expire_password`, ancienne synchronisation) une fois le mot de passe changé |
| log_events | bool | on | SIGHUP | `ereport(LOG)` sur chaque événement (préfixe `pg_pass_policy:`) |
| notify_channel | string | pg_pass_policy | SIGHUP | |
| exempt_roles | string | '' | SIGHUP | liste séparée par virgules exemptée de la politique et du verrouillage ; règles de `SplitIdentifierString()` (noms non quotés en minuscules ASCII, `"quotés"` tels quels, `""` = un guillemet, espaces ignorés), une seule implémentation en C (`ppp_role_is_exempt()`, liste découpée une fois par l'assign hook), appelée aussi par la fonction SQL `_is_exempt()` (symbole `ppp_is_exempt`) |
| superuser_bypass | bool | off | SIGHUP | si on : les superutilisateurs ne sont pas soumis à la complexité |
| require_scram | bool | on | SIGHUP | refuse MD5 (`password_encryption = md5`) |
| enforce_database | bool | on | SIGHUP | hors de `pg_pass_policy.database`, `ALTER ROLE … PASSWORD` est refusé (sinon seulement ignoré avec WARNING) |

PG ≥ 15 : `MarkGUCPrefixReserved("pg_pass_policy")`, sinon
`EmitWarningsOnPlaceholders`.

## 6. Contrat C (voir `src/pg_pass_policy.h`)

### 6.1 Propriétaires

| fichier | propriétaire | contenu |
|---|---|---|
| `pg_pass_policy.c` | agent « core » | `_PG_init`, GUC, `shmem_request_hook`/`RequestAddinShmemSpace`, `shmem_startup_hook` → `ppp_lockout_shmem_init()`, enregistrement du worker, `ppp_role_is_exempt`, `ppp_is_exempt`, `ppp_worker_status` |
| `policy.c` | agent « core » | hook mot de passe, `ppp_check_password`, `ppp_generate_password` |
| `lockout.c` | agent « lockout/worker » | hook auth, hash shmem, `ppp_failed_attempts`, `ppp_shmem_*` |
| `worker.c` | agent « lockout/worker » | bgworker |
| `compat.h`, `Makefile`, `.control` | agent « core » | |
| `sql/*.sql` | agent « sql » | |
| `test/`, `docker/` | agent « tests » | |

### 6.2 Hook mot de passe (`policy.c`)

```
static void ppp_check_password_hook(const char *username, const char *shadow_pass,
                                    PasswordType password_type,
                                    Datum validuntil_time, bool validuntil_null);
```

Algorithme :
1. si `!ppp_enabled` ou rôle exempt → chaîner au hook précédent et sortir ; sinon `superuser()` de l'appelant est lu, puis l'étape 2 est faite **sans SPI** (catalogues seulement) ; **une seule** session SPI élevée (`ppp_spi_begin()`) couvre les étapes 3 à 8 et n'est ouverte que si l'extension est installée et fiable ; en cas d'ERROR, l'identité est restaurée et l'erreur relancée avec `STATEMENT` et `CONTEXT` masqués (`ppp_rethrow_hidden()`) ;
2. état de l'extension (`ppp_require_extension()` → `ppp_extension_state()`, avant toute élévation) : absente → règle ci-dessous, sans session SPI ; présente mais non fiable (schéma `pass_policy` absent, ou dont le propriétaire n'est pas superutilisateur) → ERROR `PPP-004` (« pg_pass_policy schema is not trusted », SQLSTATE `55000`, DETAIL sur le propriétaire), jamais d'acceptation sans politique, sans session SPI ; installée et fiable → ouvrir la session SPI élevée et charger le profil effectif : `SELECT * FROM pass_policy.effective_profile($1)` (si le schéma n'existe pas dans cette base → **ne rien bloquer**, juste `ereport(WARNING)` une fois par session : l'extension n'est installée que dans `pg_pass_policy.database` ; **ATTENTION** : le hook s'exécute dans la base courante de la session, pas dans `pg_pass_policy.database`. Décision : la politique n'est appliquée que lorsque `current_database() = ppp_database` **ou** si la table est accessible localement ; en dehors, refuser `ALTER ROLE … PASSWORD` (et `CREATE ROLE … PASSWORD`) avec l'ERROR `PPP-003` (« password changes must be made while connected to database X ») si `ppp_enabled`. Ce comportement est contrôlé par le GUC `pg_pass_policy.enforce_database` (bool, défaut on ; off = simple WARNING, une fois par session) ;
3. si `password_type != PASSWORD_TYPE_PLAINTEXT` : `reject_prehashed` → ERROR `PPP-001` ; vérificateur MD5 et `pg_pass_policy.require_scram` → ERROR `PPP-002` ; sinon enregistrer sans vérification de complexité (seul `min_age` est contrôlé). Pour un mot de passe en clair, `PPP-002` est aussi levé si `require_scram` et `password_encryption = md5` ;
4. vérifications de complexité (ordre et codes) : `PPP-010` longueur min, `PPP-011` longueur max, `PPP-012` classes (min_classes), `PPP-013` min_lower, `PPP-014` min_upper, `PPP-015` min_digit, `PPP-016` min_special, `PPP-017` contient le nom du rôle, `PPP-018` dictionnaire, `PPP-019` répétitions, `PPP-020` caractères non imprimables / espace en début-fin. Codes hors complexité : `PPP-001` pré-haché refusé, `PPP-002` MD5 refusé par `require_scram`, `PPP-003` changement hors de `pg_pass_policy.database` ;
5. `min_age` : `PPP-030` si `now() - password_changed_at < min_age` (sauf superutilisateur appelant, ignoré si `must_change`) ; pour un rôle existant, les étapes 5 et 6 ne sont faites que si l'appelant peut changer son mot de passe (superutilisateur, le rôle lui-même, ou `PPP_MAY_SET_PASSWORD_OF()` de `compat.h` : `is_admin_of_role()` sur PG ≥ 16, `CREATEROLE` et cible non superutilisateur sur PG ≤ 15), droits lus avant l'élévation ; sinon elles sont sautées en silence (pas d'oracle `PPP-030`/`PPP-031`), la complexité reste contrôlée. Défense en profondeur : `CreateRole()` et `AlterRole()` vérifient l'existence et les droits avant d'appeler le hook (sources 13.2, 16.4, 17beta1) ; `role_state` cherché par OID uniquement (rôle existant) ; la date retenue est la plus récente entre `role_state.password_changed_at` et la dernière ligne `password_history` sans OID (`role_oid IS NULL`) du même nom, écrite par `CREATE ROLE … PASSWORD` avant que `run_maintenance()` crée `role_state` ;
6. historique : mot de passe actuel (`pg_authid`) puis chaque vérificateur des `history_count` derniers (l'actuel compris, et plus récents que `history_days`), `scram_verify_plain_password(username, password, verifier)` → `PPP-031` si égal ; vérificateurs MD5 : comparés via `pg_md5_encrypt`. Pour un rôle existant : lignes de son OID **et** lignes `role_oid IS NULL` de son nom (`CREATE ROLE … PASSWORD` pas encore rattaché par `run_maintenance()`), jamais celles d'un autre OID ; pour un rôle pas encore créé (`CREATE ROLE`), par nom parmi les seules lignes `role_oid IS NULL` ;
7. calcul du nouveau vérificateur : `encrypt_password(PASSWORD_TYPE_SCRAM_SHA_256, username, shadow_pass)` (PG 14-18 : `libpq/crypt.h`) ; si `password_type == PLAINTEXT` ; sinon `shadow_pass` tel quel ;
8. SPI `SELECT pass_policy.record_password_change($1, $2)` ;
9. chaîner au hook précédent.

Refus : `ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD), errmsg("PPP-0xx: …"), errdetail(…), errhint(…)))`. Le mot de passe n'apparaît **jamais** dans un message, un log ou l'audit. Un refus est journalisé (`password_rejected`, details = code) via SPI dans une sous-transaction qui ne doit pas masquer l'erreur principale (ou simplement `ereport(LOG)` si l'audit échoue).

Les caractères sont comptés en points de code UTF-8 (`pg_mblen`) ; les classes : minuscule / majuscule (`pg_wchar` + `iswlower/iswupper` ou ASCII suffisent + tout caractère non-ASCII compte comme « special »), chiffre ASCII, special = tout le reste imprimable.

### 6.3 Hook d'authentification et shmem (`lockout.c`)

Le hook s'exécute pendant `InitPostgres()`, **après** `InitCatalogCache()`,
`StartTransactionCommand()` et `GetTransactionSnapshot()` :
`PerformAuthentication()` est appelée une fois la transaction de démarrage
ouverte (vérifié dans les sources 13.2, 16.4 et 17beta1), et
`get_role_password()` y fait elle-même `SearchSysCache1(AUTHNAME)`. Le hook
peut donc consulter le cache système ; il ne fait **qu'une** recherche
(`get_role_oid(nom, true)`, avant de prendre le LWLock, sautée si
`!IsTransactionState()`), **aucun SPI**. Tout le reste vient de la shmem,
remplie par le worker.

```
static void ppp_client_auth_hook(Port *port, int status);
```

1. si `!ppp_enabled` ou rôle exempt → chaîner au hook précédent et sortir ;
2. sinon le hook précédent est appelé après l'étape 8, **avant** le FATAL de l'étape 5 (un module chargé avant nous, `auth_delay` par exemple, voit toujours la tentative et son statut réel) ;
3. si `status == STATUS_ERROR` : le rôle existe-t-il (`get_role_oid`) ?
4. `LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE)` ; chercher `port->user_name` dans `ppp_role_hash` ; si absent **et** `status == STATUS_ERROR` → créer avec les paramètres par défaut (`ppp_shared->default_*`) en mode « comptage » (`ppp_enter_role(…, PPP_ENTER_COUNT, …)`, voir « Hash plein » ci-dessous) ; faute de place → `ereport(LOG)` et continuer sans compter (un verrou existant reste appliqué : il a toujours une entrée) ; `role_missing` reçoit le résultat de l'étape 3 à la création **et à chaque échec** (un rôle créé après coup perd le drapeau), et est effacé par un succès ;
5. si `locked_until > now` (ou `DT_NOEND`) → `ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("role \"%s\" is locked by pg_pass_policy"), errdetail("locked until %s")))` — **même si status == STATUS_OK** ;
6. si `status == STATUS_OK` → `failed_count = 0` ;
7. sinon (`STATUS_ERROR` d'une méthode qui vérifie un mot de passe ou un secret uniquement, voir « Méthodes comptées » ci-dessous et §11) : si la fenêtre est écoulée (`ppp_window_elapsed()`) → repartir à 0 ; incrémenter ; si `failed_count >= max_failures` et `max_failures > 0` → `locked_until = now + lock_duration` (ou `DT_NOEND`), `lock_pending_audit = true`, `audit_locked_until = locked_until`, `ereport(LOG, "pg_pass_policy: role \"%s\" locked after %d failed attempts")` ;
8. `LWLockRelease`.

**Méthodes comptées.** Seuls les échecs des méthodes où le client présente
un mot de passe ou un secret sont comptés : `password`, `md5`,
`scram-sha-256`, `ldap`, `pam`, `radius`, `bsd`
(`ppp_auth_method_checks_secret()`, `port->hba->auth_method`, valeurs de
l'enum `UserAuth` identiques de 13 à 17beta1, `port->hba` vérifié non NULL).
Un échec `peer`, `ident`, `cert`, `gss` ou `sspi` n'est pas une tentative de
mot de passe : le compter permettrait à quiconque atteint le serveur de
verrouiller n'importe quel rôle par son nom (avec `ident`, le client peut
contrôler le serveur identd interrogé). Les lignes `reject` et le rejet
implicite (aucune ligne) n'atteignent pas le hook : `ClientAuthentication()`
lève son FATAL dans le `switch`, avant l'appel (vérifié dans 13.2, 16.4 et
17beta1). Une méthode ajoutée plus tard (`oauth` en PG 18) n'est pas comptée
tant qu'elle n'est pas ajoutée à la liste. Le refus d'un rôle verrouillé
(étape 5) s'applique quelle que soit la méthode, `trust` compris. Avec
`clientcert=verify-full` sur une ligne à mot de passe, un certificat valide
mais au mauvais nom échoue avec la méthode de la ligne et est compté.

**Noms inexistants.** Ils sont comptés et « verrouillés » exactement comme les
vrais rôles : après `max_failures` échecs le client reçoit le même FATAL
« role "x" is locked by pg_pass_policy ». Répondre autrement offrirait un
oracle d'énumération des rôles (PostgreSQL simule de même un échange SCRAM
pour un rôle inexistant). Leur entrée porte `role_missing` et est **toujours
évincable**, même « verrouillée » ou avec des échecs pas encore journalisés :
perdre le pseudo-verrou ou l'audit `auth_failed` d'un nom inexistant est
acceptable (le nom ne peut pas se connecter, le log serveur garde les
échecs), alors que les garder permettrait à un flot de noms fantômes
d'occuper le hash et d'empêcher le comptage des vrais rôles.

Verrou expiré (`locked_until` passé) rencontré par le hook ou par le
worker : fonction unique `ppp_expire_lock(entry, now, check_inflight)`. Les
compteurs de l'épisode qui a mené au verrou (`first_failure_at <
locked_until`) sont remis à zéro une seule fois ; `locked_until` n'est effacé
que si le worker a déjà journalisé le verrou (`!lock_pending_audit`), sinon
il est conservé (sans bloquer : `ppp_is_locked()` est faux) et les nouveaux
échecs sont comptés normalement, un nouveau verrou pouvant être posé avant
le passage du worker. Le worker (`check_inflight`) laisse en plus de côté une
entrée dont le verrou, appliqué en PRE_COMMIT, n'est pas encore validé.

**Perte bornée de l'audit d'un verrou expiré.** Une entrée dont le verrou a
expiré et dont l'audit `role_locked` est toujours en attente n'est plus
`KEEP` quand ce verrou a pris fin depuis plus de 24 h
(`PPP_STALE_AUDIT_SECS` ; pour un verrou manuel levé depuis, 24 h après sa
pose, `lock_set_at`), ou tout de suite sur un hot standby (la ligne ne peut
pas être écrite avant une promotion) : elle est alors classée sur son seul
compteur (`INACTIVE` ou `LIVE_COUNTER`), ses échecs non journalisés compris.
Sans cela, un worker qui ne peut pas écrire (standby, `pg_pass_policy.database`
mal configurée) laisserait `max_tracked_roles` vrais rôles verrouillés une
fois remplir le hash pour de bon. Le worker ne la purge jamais de lui-même :
elle n'est perdue que si la place est nécessaire, avec un LOG « evicted
before its lock was audited » (nom du rôle, échecs perdus). La perte est
bornée à ces entrées-là ; le log serveur garde les échecs et le LOG du
verrou (`log_events`).

**Classes d'entrées** (`ppp_entry_class()`, `pg_pass_policy.h` : définition
unique utilisée par le hook, l'éviction et la purge du worker), de la moins
coûteuse à perdre à la plus coûteuse :

| classe | entrée |
|---|---|
| `GHOST` | `role_missing` (quel que soit son état) |
| `INACTIVE` | compteur nul ou fenêtre écoulée, rien à journaliser, pas de verrou actif, pas de profil ; ou verrou expiré à l'audit périmé (voir ci-dessus) et compteur inactif |
| `LIVE_COUNTER` | compteur encore dans sa fenêtre (ou sans fenêtre) |
| `PENDING_AUDIT` | échecs pas encore journalisés (`pending_failures > 0`) |
| `KEEP` | verrou actif, `lock_pending_audit` (sauf audit périmé, ci-dessus) ou `from_profile` : jamais évincée |

**Hash plein (fail-closed).** Il n'y a pas de réserve : toutes les
`max_tracked_roles` entrées servent indifféremment. Une fois le hash plein,
`ppp_enter_role()` évince l'entrée la moins récemment en échec
(`last_failure_at`) de la classe la moins coûteuse autorisée par le mode :

- `PPP_ENTER_COUNT` (hook) : `GHOST` puis `INACTIVE`. Évincer un compteur
  vivant permettrait de remettre à zéro le compteur du rôle attaqué en
  essayant d'autres noms *existants* ; les noms inexistants, eux, ne peuvent
  jamais bloquer le comptage d'un vrai rôle ;
- `PPP_ENTER_PRIORITY` (verrou `shmem_lock_role`, réinjection depuis
  `role_state`, profil) : en plus `LIVE_COUNTER` puis `PENDING_AUDIT` (LOG du
  nombre d'échecs perdus) ;
- si le hash est entièrement occupé par des entrées `KEEP` (verrous actifs
  et profils de vrais rôles), le hook ne compte pas (LOG « cannot track ») et
  `lock_role()` lève une ERROR (ci-dessous) : `max_tracked_roles` doit
  dépasser le nombre de rôles LOGIN qui ont un profil ou un verrou ;
- coût : l'éviction parcourt tout le hash sous le verrou exclusif, et
  seulement une fois le hash plein. Quand un parcours en mode COUNT n'a rien
  trouvé, `ppp_shared->evict_failed_at` est posé et le hook ne reparcourt
  pas pendant 1 seconde (échecs non comptés pendant ce délai, LOG au plus
  une fois par seconde) ; le mode PRIORITY parcourt toujours.

**Écritures différées et course PRE_COMMIT/COMMIT.** Les demandes
`shmem_lock_role` / `shmem_unlock_role` / `shmem_reset_failures` sont mises
en file pendant la transaction (annulées par `ROLLBACK [TO SAVEPOINT]`) :

- les `PPP_OP_LOCK` sont appliqués en `XACT_EVENT_PRE_COMMIT`, sous un seul
  maintien du LWLock exclusif, en mode PRIORITY : entre la recherche de
  place et l'écriture, aucune autre insertion (hook, autre `lock_role`,
  rechargement du worker) ne peut prendre la place. Faute de place, les
  verrous déjà appliqués par cet appel sont défaits (dans l'ordre inverse :
  contenu antérieur restauré, entrées créées retirées et les entrées
  qu'elles avaient évincées réinsérées, `pppEviction.victim`) et `ERROR 53400`
  « cannot lock role "x": pg_pass_policy shared memory is full » est levée :
  la transaction est annulée (`role_state`, audit), `lock_role()` échoue
  visiblement. Une transaction sans `PPP_OP_LOCK` ne prend pas le LWLock à
  cette étape ;
- les `PPP_OP_UNLOCK` et `PPP_OP_RESET` sont appliqués en
  `XACT_EVENT_COMMIT`, une fois la transaction durable ; un verrou et un
  déverrouillage du même rôle dans la même transaction sont résolus dans
  l'ordre (le dernier l'emporte) ;
- un `PPP_OP_UNLOCK` ne lève pas un verrou plus récent que la demande
  (`ppp_unlock_allowed()`) : la pose d'un verrou est horodatée
  (`pppRoleEntry.lock_set_at`, par le hook et en PRE_COMMIT) et la demande
  aussi (`pppPendingOp.queued_at`) ; au COMMIT, un verrou actif n'est levé
  que s'il est reflété dans `role_state` (`lock_from_state` : le verrou de
  ligne de `role_state` ordonne déjà `unlock_role()` et `lock_role()`) ou
  s'il a été posé avant la demande (`lock_set_at <= queued_at`). Un verrou
  automatique posé par de nouveaux échecs entre l'UPDATE de `role_state` et
  le COMMIT est conservé (LOG « unlock … not applied ») et recopié dans
  `role_state` par le worker. Avec `expired_only` (étape f de
  `run_maintenance()`, `_shmem('unlock_expired')`), seul un verrou expiré
  est levé : l'étape f lève les verrous expirés **dans `role_state`**, alors
  que la shmem peut porter un nouveau verrou automatique, posé avant ou
  pendant la passe, que `role_state` ne connaît pas encore ;
- si la transaction échoue entre PRE_COMMIT et COMMIT (très rare : erreur
  d'une étape ultérieure de `CommitTransaction()`, par exemple
  `PreCommit_on_commit_actions` ou `PreCommit_Notify`), le verrou reste en
  shmem sans ligne `role_state` : fail-closed, levé par `unlock_role()` ou
  par le rechargement suivant du worker (l'entrée porte `lock_from_state`,
  voir ci-dessous) ;
- `lock_inflight` / `lock_seq` : l'entrée est marquée « en cours » de
  PRE_COMMIT à COMMIT/ABORT, puis estampillée avec un compteur partagé
  (`ppp_shared->lock_seq`, incrémenté sous le LWLock au COMMIT/ABORT d'un
  verrou et au COMMIT d'un déverrouillage). Le worker lit ce compteur
  **avant** de prendre l'instantané (`GetLatestSnapshot()`) du rechargement :
  une entrée en cours ou estampillée plus tard a changé après l'instantané et
  n'est ni écrasée ni levée par ce rechargement. Un `lock_role()` validé
  après l'instantané du worker n'est donc jamais levé ;
- `PREPARE TRANSACTION` est refusé (`0A000`) s'il reste des écritures en
  attente.

Le worker, à chaque tour, parcourt le hash : écrit les lignes d'audit
`auth_failed` / `role_locked` en attente (`lock_pending_audit`) et copie
`locked_until` vers `role_state` dans une transaction dédiée, puis
**acquitte la shmem seulement après le COMMIT** (`pending_failures`
décrémenté, `lock_pending_audit` effacé si `audit_locked_until` n'a pas
changé). Le `role_locked` d'un verrou automatique est écrit avec
`audit_locked_until` même si le verrou a été levé (`unlock_role()`) ou
remplacé (`lock_role()`) avant le passage du worker : ni `PPP_OP_UNLOCK`, ni
`PPP_OP_LOCK`, ni le rechargement n'effacent `lock_pending_audit` ; la copie
vers `role_state` n'est faite que si `locked_until = audit_locked_until`
(sinon `details.lifted_before_audit = true`). Les entrées `role_missing` ne
produisent pas une ligne par nom : une seule ligne `auth_failed` par tour,
`role_name` NULL, `details = {"unknown_roles": n, "attempts": total,
"pseudo_locks": k, "last_failure_at": …, "source": "auth_hook"}` (un seul
NOTIFY), leurs pseudo-verrous compris (aucune ligne `role_locked` ni
`role_state` pour un nom inexistant) ; les vrais rôles restent journalisés
un par un ;
dans une seconde transaction il efface les verrous expirés déjà journalisés
(en gardant les échecs comptés après l'expiration), purge les entrées
`INACTIVE` qui n'ont rien à journaliser, les compteurs sans fenêtre (`failure_window` ≤ 0) dont le dernier
échec date de plus de 24 h, et les entrées `role_missing` sans verrou actif
ni rien à journaliser dont le dernier échec est plus ancien que leur
`failure_window` (24 h si la fenêtre est ≤ 0) ; aucune requête n'est faite
pour cela (l'existence des rôles est connue du hook). Il réinjecte ensuite
les verrous de `role_state` **avant** de recharger les paramètres des
profils (`max_failures`, `failure_window`, `lock_duration`, bornés à
2^31 − 1 s ≈ 68 ans avant conversion en `int4`) pour chaque rôle de
`role_profile` + les valeurs du profil `default` dans `ppp_shared->default_*`.
Un verrou `lock_from_state` (réinjecté depuis `role_state`, ou posé par
`shmem_lock_role()` sur un primaire) qui ne figure plus dans `role_state` est
levé, sur le primaire comme sur un standby ; les verrous automatiques du hook
(`lock_from_state = false`) ne sont jamais levés par le rechargement. Un
appel direct à `shmem_lock_role()` sur un primaire, sans ligne `role_state`,
est donc levé au rechargement suivant (utiliser `lock_role()`) ; sur un
standby, un tel verrou local n'est pas marqué `lock_from_state` et survit
aux rechargements.

Au démarrage (`shmem_startup`), le hash est vide ; le worker réinjecte les
verrous manuels/actifs depuis `role_state` lors de son premier tour.

### 6.4 Worker (`worker.c`)

- enregistré dans `_PG_init` via `RegisterBackgroundWorker` (`BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION`, `BgWorkerStart_ConsistentState` pour tourner aussi sur un hot standby, `bgw_restart_time = 10`) ;
- `ppp_worker_main` : `BackgroundWorkerInitializeConnection(ppp_database, NULL, 0)` puis `search_path = pg_catalog, pg_temp` (le worker est superutilisateur : toutes ses requêtes sont qualifiées, `pg_catalog.jsonb_build_object` compris), boucle `WaitLatch` avec `ppp_worker_interval` ; sur `reload_requested` ou SIGHUP → tour immédiat ;
- la base `pg_pass_policy.database` doit exister au démarrage : sinon `BackgroundWorkerInitializeConnection` lève le FATAL standard « database "x" does not exist » et le postmaster relance le worker toutes les 10 s (comportement standard des bgworkers, identique à pg_cron) ; le GUC étant `postmaster`, corriger puis redémarrer ;
- chaque tour : `StartTransactionCommand` → si l'extension n'est pas installée (`get_extension_oid("pg_pass_policy", true) == InvalidOid`) → attendre ; sinon `SPI_execute("SELECT * FROM pass_policy.run_maintenance()")`, puis synchronisation shmem (§6.3) ; `CommitTransactionCommand`. `run_maintenance()` prend `pg_advisory_xact_lock(hashtext('pg_pass_policy.run_maintenance'))` en tête : une passe du worker, de pg_cron ou manuelle attend la fin d'une passe concurrente au lieu d'agir sur les mêmes lignes (audits et NOTIFY en double) ;
- l'étape d'audit regroupe les noms inexistants (`role_missing`) en une ligne `auth_failed` par tour (§6.3) : un flot de noms inventés ne produit plus une ligne et un NOTIFY par nom ;
- sur un hot standby (`RecoveryInProgress()`), tour en **lecture seule** (`ppp_worker_cycle_standby`) : ni `run_maintenance()` ni l'étape d'audit en attente (elles écrivent) ; les échecs et verrous comptés localement par le hook **ne sont pas acquittés** : `pending_failures` et `lock_pending_audit` restent posés (les entrées de vrais rôles concernées ne sont alors pas évincables par le hook, c'est voulu, sauf celles dont le verrou a expiré : sur un standby leur audit est aussitôt « périmé » et elles redeviennent évincables, voir « Perte bornée » §6.3 ; un verrou local expiré n'est pas effacé par le worker mais ne bloque plus, voir « verrou expiré » §6.3) et le premier tour après promotion les écrit dans `audit_log` et `role_state`. Puis nettoyage + rechargement **forcé à chaque tour** (`shmem_reload()` du primaire ne peut pas atteindre le worker du standby) : SELECT uniquement, dans une transaction que PostgreSQL force en lecture seule pendant la récupération. Intervalle : `worker_interval`, 60 s s'il vaut 0 (le standby doit sonder, rien ne le réveille). Un verrou réinjecté depuis `role_state` (`lock_from_state`) qui n'y figure plus est levé (unlock ou expiration sur le primaire) ; les verrous posés localement (hook, ou `shmem_lock_role()` sur le standby) ne sont pas levés par le rechargement : ils expirent selon `lock_duration`, ou un superutilisateur appelle `pass_policy.shmem_unlock_role()` sur le standby (fonctionne en lecture seule). Après promotion, le tour suivant est un tour normal avec audit des échecs et verrous en attente et rechargement complet ;
- sans `hot_standby`, aucune connexion n'est acceptée pendant la récupération : le worker démarre à la fin de celle-ci ;
- `pg_pass_policy.worker_interval = 0` → le worker dort indéfiniment (réveil sur SIGHUP).

### 6.5 Compatibilité (`compat.h`)

- PG 15+ : `shmem_request_hook` ; PG 14 : `RequestAddinShmemSpace` + `RequestNamedLWLockTranche` dans `_PG_init` ;
- PG 15+ : `MarkGUCPrefixReserved` ; PG 14 : `EmitWarningsOnPlaceholders` ;
- `scram_verify_plain_password(const char *username, const char *password, const char *secret)` : disponible 14→18 (`libpq/scram.h`) ;
- `encrypt_password(PasswordType, const char *role, const char *password)` : `libpq/crypt.h`, 14→18 ;
- `get_password_type` : `libpq/crypt.h` ;
- PG 17/18 : vérifier `BackgroundWorkerInitializeConnection` flags, `pg_strong_random`, `GetCurrentTimestamp` inchangés ; PG 18 : `password_encryption` md5 déprécié (warning) ;
- Utiliser `PG_VERSION_NUM` uniquement dans `compat.h`.

## 7. Tests

- `make check` **n'est pas supporté par PGXS** (il affiche « "make check" is not supported » et renvoie 0). `shared_preload_libraries` impose un serveur dédié : la cible est `make installcheck`, dont `REGRESS_OPTS` contient `--temp-instance=test/tmp_check` et `--temp-config=test/pg_pass_policy.conf` (`shared_preload_libraries = 'pg_pass_policy'`, `pg_pass_policy.database = 'contrib_regression'`, `worker_interval = 0`) ; pg_regress crée et arrête lui-même l'instance temporaire. `make test` = `make install` + `make installcheck` + `test/shell/run-all.sh` ;
- fichiers pg_regress : `setup`, `profile`, `complexity`, `history`, `generate`, `rotation`, `pair`, `lock_unlock`, `maintenance`, `audit`, `privileges`, `teardown` ;
- `test/shell/lockout.sh` (`fsync = on`) : vraies connexions `psql` avec `PGPASSWORD` erroné → vérifie le FATAL « locked », l'expiration du verrou, `unlock_role`, l'application effective des paramètres rechargés (`max_failures = 2`), le verrou expiré avant le passage du worker (audit conservé, reverrouillage), `lock_duration` de 100 ans et NULL, `lock_role`/`unlock_role` sous ROLLBACK et SAVEPOINT ;
- `test/shell/expiry.sh` : profil `max_age = '1 second'`, attend le worker, vérifie `rolvaliduntil` et le refus de connexion ;
- `test/shell/auto_explain.sh` : `auto_explain` chargé avec `log_nested_statements` et `log_verbose` → aucun mot de passe ni vérificateur SCRAM dans le log serveur ;
- `test/shell/unicode.sh` : instance en `C.UTF-8` (`PPP_LOCALE`), `PPP-017` / `PPP-018` insensibles à la casse sur des lettres non ASCII ;
- `docker/compose.yml` : services `pg14`…`pg18` construits depuis `docker/Dockerfile` (`ARG PG_MAJOR`, image `postgres:${PG_MAJOR}`, installe `postgresql-server-dev-${PG_MAJOR}` + build-essential, compile, `make installcheck` sur instance temporaire, puis les tests shell) ; `docker/run-all.sh` lance la matrice et résume.

## 8. Sécurité (règles non négociables)

1. Aucun mot de passe en clair n'est stocké, journalisé, ni inclus dans un message d'erreur, un `NOTIFY` ou l'audit.
2. `rotate_password` / `switch_rotation_pair` retournent le mot de passe à l'appelant **une seule fois**. Le mot de passe est généré côté serveur et n'apparaît donc jamais dans le texte d'une requête (donc jamais dans `log_statement`), seulement dans le résultat.
3. Toutes les constructions SQL dynamiques utilisent `format('%I'/'%L')`.
4. Les fonctions d'administration vérifient `pg_has_role(session_user, 'pass_policy_admin', 'MEMBER') OR rolsuper` ; un administrateur non superutilisateur ne peut pas viser un rôle privilégié, directement ou par appartenance (§4).
5. Les mémoires contenant un mot de passe en C sont effacées (`explicit_bzero` si dispo, sinon boucle volatile) avant `pfree`, y compris sur les chemins d'erreur (`PG_TRY/PG_FINALLY`). La mise en minuscules (`ppp_lower`) se fait dans des tampons de l'extension, effacés : en UTF-8 avec une locale non C par `pg_wchar` + `towlower()` sur le `LC_CTYPE` du backend (même résultat que `str_tolower()` avec le provider libc ; avec un provider ICU par défaut, la casse spéciale ICU n'est pas appliquée) ; pour un autre encodage multi-octets, `str_tolower()` est conservé et laisse une copie `wchar_t` non effacée dans le cœur. PostgreSQL lui-même conserve d'autres copies hors de portée de l'extension (texte de l'instruction dans `MessageContext`, `pg_saslprep` dans `encrypt_password`).
6. `generate_password` utilise exclusivement `pg_strong_random`.
7. `auto_explain` (`log_nested_statements`) journaliserait les paramètres des requêtes SPI du hook (`record_password_change($1, $2)`, `$2` = vérificateur SCRAM) : `auto_explain.log_min_duration` est mis à -1 (`GUC_ACTION_SAVE` / `set_config(…, true)`) pendant les requêtes SPI du hook, dans `_set_password()` et dans `run_maintenance()`, jusqu'à la sortie de la fonction. `check_password(role, password)` reçoit le mot de passe en argument : ses ERROR (extension absente ou non fiable, profil introuvable…) sont relancées avec `STATEMENT`/`CONTEXT` masqués et ses messages émis sous la même garde GUC que le hook ; en revanche la journalisation de la requête englobante (`log_statement`, `log_min_duration_statement` avec `log_parameter_max_length = -1` par défaut depuis PG 13, même pour un paramètre lié) n'est pas sous le contrôle de l'extension (README).

## 9. CLI (`cli/`, Rust, clap + sqlx + tokio, nom du binaire `pgpp`)

Commandes : `status [--role] [--format table|json]`, `expiring [--within 14d]`,
`locked`, `rotate <role> [--length N] [--exec CMD] [--vault-kv PATH]`,
`switch-pair <pair> [--exec] [--vault-kv]`, `lock <role> [--for 30m]`,
`unlock <role>`, `profile list|show|create|alter|assign`, `audit [--since]
[--role] [--type]`, `check <role>` (lit le mot de passe sur stdin),
`maintenance`. Connexion via `PG*`/`DATABASE_URL`. Intégration coffre : écriture
HashiCorp Vault KV v2 (`VAULT_ADDR`, `VAULT_TOKEN`) ; `--exec` passe le mot de
passe **sur stdin** du processus, jamais en argument. Le mot de passe n'est
affiché que si `--show`. `rotate` et `switch-pair` exigent au moins une option
de remise (`--show`, `--exec` ou `--vault-kv`), sinon la commande est refusée
avec le code de sortie 2 **avant** toute connexion : une rotation dont le
résultat ne serait remis nulle part serait perdue. Codes de sortie : 0 succès,
1 erreur, 2 usage, 3 mot de passe refusé par `check`.

## 10. Web (`web/`, FastAPI + HTMX + Jinja2, psycopg 3, venv)

Pages : tableau de bord (compteurs ok/warning/grace/expired/locked), rôles
(table filtrable, actions lock/unlock/expire/rotate avec affichage unique),
profils (CRUD), audit (filtres, pagination), paires de rotation. Auth : HTTP
basic ou en-tête reverse-proxy (`REMOTE_USER`), rôle PG dédié membre de
`pass_policy_admin`. Tests pytest contre une base de test.

## 11. Décisions d'intégration (journal)

- **Nom du schéma : `pass_policy`** (le préfixe `pg_` est réservé aux schémas système : `CREATE EXTENSION` échouait). Les rôles sont `pass_policy_admin` et `pass_policy_viewer` (même raison : `pg_` réservé pour les rôles). L'extension, la bibliothèque et le préfixe des GUC restent `pg_pass_policy`. En C, utiliser la macro `PPP_SCHEMA`.
- `role_state` porte une contrainte UNIQUE/PK sur `role_oid` (le worker fait `ON CONFLICT (role_oid)`), et les colonnes `role_name`, `locked_until`, `locked_by`, `lock_reason`.
- `lock_role` / `unlock_role` mettent à jour **d'abord** `role_state` puis la shmem : `run_maintenance()` appelle `shmem_reload()` et le worker réinjecte `role_state.locked_until` à chaque rechargement, donc un `shmem_unlock_role` sans mise à jour de `role_state` serait annulé au tour suivant.
- Purge des rôles disparus : `role_profile`, `role_state`, `password_history`, `rotation_pair`.
- `audit()` : `actor = 'worker'` quand `pg_backend_pid()` est le pid du worker (via `_worker_pid()` depuis la (revue finale) E9, `worker_status()` auparavant), sinon `session_user`.
- Le hook d'authentification ne compte pas `STATUS_EOF` (client parti avant d'envoyer le mot de passe) : seuls les échecs réels (`STATUS_ERROR`) comptent.
- `failure_window` ≤ 0 = pas de fenêtre (les échecs s'additionnent jusqu'au prochain succès).
- Un superutilisateur peut être verrouillé : documenter `pg_pass_policy.exempt_roles = 'postgres'` dans le README.
- `ppp_failed_attempts` est construite avec un tuplestore manuel (même code 14 → 18).
- (agent sql) Nouvelle fonction **C** `pass_policy._in_password_hook() RETURNS bool` (symbole `ppp_in_password_hook`, non STRICT, sans argument) : renvoie `true` uniquement pendant l'exécution du `check_password_hook` de pg_pass_policy dans ce backend (drapeau statique posé/retiré en `PG_TRY/PG_FINALLY` autour des appels SPI du hook). `record_password_change()` et `audit()` sont `GRANT EXECUTE TO PUBLIC` mais refusent l'appel hors hook si `session_user` n'est ni superutilisateur ni membre de `pass_policy_admin` : sinon un utilisateur pourrait repousser sa propre expiration sans changer de mot de passe. *Remplacé* : plus aucun droit à PUBLIC, voir (code-review) S6.
- (agent sql) `role_state.verifier_pending bool NOT NULL DEFAULT false` : posé par `record_password_change()`. Le vérificateur calculé par le hook et celui que PostgreSQL stocke ensuite diffèrent (sel SCRAM différent) ; `run_maintenance()` remplace alors simplement la ligne d'historique par `pg_authid.rolpassword` sans considérer qu'il y a eu un changement hors hook.
- (agent sql) `password_history.role_oid` est NULL pour un `CREATE ROLE … PASSWORD` (le hook s'exécute avant la création du rôle) ; `run_maintenance()` rattache ensuite l'OID par nom et crée `role_state`.
- (agent sql) Les tables sont `REVOKE ALL FROM PUBLIC` et `password_history.verifier` n'est lisible par personne d'autre que le propriétaire : le code C qui lit `dictionary`, `password_history` ou `role_state` (hook, `check_password`) doit le faire avec les droits du propriétaire de l'extension (`SetUserIdAndSecContext`), sauf via `effective_profile()` / `record_password_change()` (SECURITY DEFINER). `USAGE` sur le schéma est accordé à PUBLIC (*remplacé* : retiré, voir (code-review) S6).
- (agent core) Codes ajoutés : `PPP-002` (MD5 refusé par `require_scram`), `PPP-003` (changement de mot de passe hors de `pg_pass_policy.database` avec `enforce_database = on` ; s'applique aussi à `CREATE ROLE`).
- (agent core) Fonction C `pass_policy._in_password_hook()` (`ppp_in_password_hook`) : true seulement pendant le hook (PG_TRY/PG_FINALLY).
- (agent core) Les SPI du hook tournent en `BOOTSTRAP_SUPERUSERID` (`SECURITY_LOCAL_USERID_CHANGE`), `search_path = pg_catalog, pg_temp`, et avec `log_min_error_statement = panic` pour que le `STATEMENT:` contenant le mot de passe ne soit jamais journalisé ; les ereport du hook utilisent `errhidestmt(true)`.
- (agent core) Dictionnaire : seuls les mots de même longueur sont chargés par SPI et comparés en C (le mot de passe ne transite jamais vers le SQL). Correspondance exacte, insensible à la casse. *Remplacé* par la recherche sur digest, voir (code-review) C5.
- (agent core) `PPP-017` ignoré si le nom de rôle fait moins de 3 caractères. `superuser_bypass` ne dispense que de la complexité (jamais de l'historique). `min_age` ignoré si `must_change`.
- (agent core) L'audit `password_rejected` en table est annulé par le rollback de l'ERROR : seule la ligne LOG subsiste. Une file shmem vidée par le worker serait nécessaire pour une trace en table (non implémenté).
- (agent core) `reject_prehashed = true` bloque `\password` de psql et la restauration d'un `pg_dumpall` : documenter `pg_pass_policy.enabled = off` pendant une restauration.
- (finition) Avec `pg_pass_policy.worker_interval = 0`, le worker réveillé par `shmem_reload()` (donc par `assign_profile`, `lock_role`, `run_maintenance`…) ne fait **que** la resynchronisation de la mémoire partagée (`ppp_worker_cycle(run_full = false)`), jamais `run_maintenance()` : en pg_regress seuls les appels explicites à `run_maintenance()` agissent.
- (finition) `CREATE ROLE … PASSWORD` : le hook s'exécute avant que le rôle existe ; l'historique est enregistré avec `role_oid = NULL` et `role_state` n'est créé qu'au `run_maintenance()` suivant (qui rattache l'OID par nom). D'ici là, `v_role_status` affiche `unknown` pour ce rôle.
- (finition) `pg_pass_policy.enabled` et `pg_pass_policy.superuser_bypass` sont de contexte **SIGHUP** : `SET` est refusé, il faut `ALTER SYSTEM SET …` (ou postgresql.conf) puis `pg_reload_conf()`.
- (finition) Un client dont le mot de passe est expiré (`rolvaliduntil` dépassé, posé par le worker ou `expire_password`) reçoit seulement « password authentication failed for user … » ; la cause (« User "x" has an expired password ») n'apparaît que dans le log serveur. Même chose pour un verrou : le client reçoit le FATAL « role "x" is locked by pg_pass_policy ».
- (revue) Le worker acquitte la shmem (`pending_failures`, `lock_pending_audit`) **après** le COMMIT de la transaction « pending audit », distincte de celle du nettoyage/rechargement : une erreur (rechargement, COMMIT) ne perd plus d'audit `auth_failed`/`role_locked` ni de verrou à copier dans `role_state`.
- (revue) `extract(epoch FROM …)` des durées de profil est borné à 2^31 − 1 s (`LEAST(COALESCE(…, -1), 2147483647)::int4`, COALESCE avant LEAST pour garder −1 = manuel) : un `lock_duration` de 100 ans (ou `infinity`) ne casse plus le rechargement.
- (revue) `shmem_reload()`, `shmem_lock_role()`, `shmem_unlock_role()` et `shmem_reset_failures()` n'agissent qu'au COMMIT de la transaction appelante (`RegisterXactCallback` / `RegisterSubXactCallback`, inscrits une fois par backend ; liste en `TopTransactionContext`, `ROLLBACK TO SAVEPOINT` retire les demandes de la sous-transaction) : le signal au worker part quand les lignes sont visibles (sinon il rechargeait l'état antérieur et consommait la demande), et `BEGIN; lock_role(); ROLLBACK` ne laisse plus de verrou fantôme en shmem. `PREPARE TRANSACTION` est refusé (`0A000`) s'il reste des écritures shmem en attente ; une demande de rechargement y est simplement abandonnée. Hash plein : WARNING au COMMIT (plus d'ERROR) ; *remplacé* depuis par l'application des verrous en `XACT_EVENT_PRE_COMMIT` (ERROR 53400, voir « fail-open n° 1 » et « revue fail-closed » ci-dessous), qui supprime le WARNING et la course résiduelle. Le worker bénéficie du même mécanisme (`_shmem('unlock')` de `run_maintenance()` appliqué au `CommitTransactionCommand`). La levée, au rechargement, des verrous `lock_from_state` absents de `role_state` est désormais faite sur le primaire aussi : la course avec un `lock_role` validé après l'instantané du worker est fermée par `lock_inflight` / `lock_seq` (§6.3).
- (revue) Hook d'authentification, verrou expiré : voir §6.3 (compteurs remis à zéro une seule fois, `locked_until` conservé tant que `lock_pending_audit`).
- (revue) `_require_target_allowed()` : définition étendue du rôle privilégié (§4) ; `create_rotation_pair()` l'applique aussi à `group_role` (un admin non superutilisateur obtenait sinon un rôle LOGIN membre de `postgres` ou de `pg_execute_server_program`). Décision : `assign_profile`/`alter_profile` restent ouvertes (option A, §4) ; `pg_pass_policy.exempt_roles` protège les superutilisateurs.
- (revue) `switch_rotation_pair()` inscrit la borne de l'ancien rôle dans `role_state` (`must_change`, `expires_at = grace_until = valid_until_synced = now() + grace_period`, `last_warned_at = now()`), comme `expire_password()`, et plus seulement par dérivation de `rotation_pair.previous_valid_until` : la disparition de la ligne de paire (groupe supprimé, DELETE) ne réactive plus l'ancien mot de passe à la synchronisation suivante. `run_maintenance()` étape a reporte `previous_valid_until` dans `role_state` avant de purger une paire (paires basculées avant cette correction). `v_role_status` affiche `grace` (et non `expired`) pour un rôle `must_change` dont `grace_until` est encore futur.
- (revue) `run_maintenance()` étape d avec `manage_valid_until = off` : mode `unblock` limité aux rôles dont `rolvaliduntil = valid_until_synced` et `must_change = false` (§5).
- (revue) `pg_pass_policy.database` inexistante : comportement standard conservé (FATAL + relance toutes les 10 s), documenté (§6.4, README).
- (finition) `DROP EXTENSION pg_pass_policy` supprime tous les objets de l'extension mais **laisse** le schéma `pass_policy` (vide) : il est déclaré par la clé `schema` du fichier `.control`, créé par `CREATE EXTENSION` sans appartenir à l'extension (comportement standard de PostgreSQL). Les rôles `pass_policy_admin` et `pass_policy_viewer` (objets globaux) survivent aussi. Désinstallation complète : `DROP EXTENSION pg_pass_policy; DROP SCHEMA pass_policy; DROP ROLE pass_policy_admin, pass_policy_viewer;`. `CREATE EXTENSION` réutilise les rôles s'ils existent (test `99_teardown`).
- (security-review) Le hook `check_password_hook` n'applique la politique (et n'exécute des SPI en superutilisateur) que si l'extension `pg_pass_policy` est installée dans la base courante, que son schéma est bien `pass_policy` et que ce schéma appartient à un superutilisateur (`ppp_extension_installed()`). Un schéma homonyme créé par le propriétaire d'une autre base n'est jamais exécuté (test dans `90_privileges`).
- (security-review, fail-open n° 1) Hash shmem plein : un client non authentifié remplissait le hash avec des noms inexistants (une entrée par nom, purgée après 24 h) ; `lock_role()` ne posait alors qu'un WARNING au COMMIT, la réinjection depuis `role_state` était abandonnée (« could not be loaded ») et l'auto-verrouillage des nouveaux rôles cessait : `role_state`/`v_locked` disaient « verrouillé » mais l'authentification passait. Première correction : réserve de ~10 % pour les verrous et profils, éviction LRU, vérification de capacité en `XACT_EVENT_PRE_COMMIT`, `role_missing` calculé par le worker (requête `pg_roles` à chaque tour), réinjection des verrous avant les profils ; *remplacée* par la « revue fail-closed » ci-dessous. Test : `test/shell/hashfull.sh`.
- (security-review, fail-open n° 2) Hot standby : le worker (`BgWorkerStart_RecoveryFinished`) ne démarrait pas pendant la récupération et la boucle sautait de toute façon les tours (`!RecoveryInProgress()`) ; la shmem du standby n'était jamais remplie et un rôle verrouillé sur le primaire se connectait librement au réplica. Correction (§6.4) : `BgWorkerStart_ConsistentState` et tour en lecture seule (nettoyage + rechargement forcé à chaque tour). Choix du rechargement forcé plutôt que d'une détection de changement (`max(updated_at)`, compteur) : trois SELECT par intervalle, sans colonne ni état supplémentaire, et aucun risque de rater une modification ; la latence est d'au plus un `worker_interval` plus le retard de réplication. Un verrou réinjecté qui a disparu de `role_state` est levé (sur le standby, puis aussi sur le primaire depuis la « revue fail-closed »). Les échecs et verrous comptés sur le standby restent en attente et sont audités après promotion (d'abord acquittés avec un simple LOG : *remplacé*, voir ci-dessous). Test : `test/shell/standby.sh` (pg_basebackup -R, second port, promotion, environ 25 s).
- (security-review) `record_password_change()` n'est appelable que depuis le hook (`_in_password_hook()`), y compris pour un superutilisateur : un appel direct par un admin non superutilisateur repoussait l'expiration d'un compte superutilisateur sans passer par `_require_target_allowed()`.
- (revue fail-closed, 10 constats) Corrections du mécanisme précédent, §6.3 et §6.4 :
  1. un flot de noms inexistants bloquait le comptage d'un vrai rôle jusqu'au tour suivant du worker (les entrées fantômes, compteur vivant et échecs non journalisés, n'étaient pas évincables avant d'avoir été marquées par le worker ; reproduit : 16 fantômes puis 5 échecs sur un vrai rôle → aucun compteur, connexion acceptée). Le hook vérifie désormais lui-même l'existence du rôle (`get_role_oid(nom, true)` : le cache système est disponible pendant `PerformAuthentication()`, comme pour `get_role_password()`), à la création de l'entrée et à chaque échec ; une entrée `role_missing` est toujours évincable, même pseudo-verrouillée. Les noms inexistants restent comptés et « verrouillés » (réponse uniforme, pas d'oracle d'énumération) ;
  2. la réserve de 10 % (`ppp_count_entry_limit()`) est supprimée : elle désactivait le comptage dès que verrous et profils dépassaient 90 % du hash. L'éviction par classe suffit ; `max_tracked_roles` doit dépasser le nombre de rôles LOGIN avec profil ou verrou ;
  3. les verrous sont appliqués en `XACT_EVENT_PRE_COMMIT` (et non plus seulement vérifiés) : plus de course entre la vérification et l'écriture au COMMIT, plus de WARNING résiduel. Déverrouillage et remise à zéro restent au COMMIT. Un échec entre PRE_COMMIT et COMMIT laisse un verrou fail-closed, levé par le rechargement suivant ;
  4. le parcours d'éviction sous verrou exclusif n'est pas répété pendant 1 s après un échec en mode COUNT (`evict_failed_at`) ;
  5. le worker ne construit plus de tableau de `max_tracked_roles` noms ni de requête `unnest()`/`pg_roles` à chaque tour ;
  6. une transaction sans `PPP_OP_LOCK` ne parcourt plus le hash au PRE_COMMIT (l'ancienne vérification était en O(N × opérations)) ;
  7. sur un standby, les échecs et verrous locaux ne sont plus acquittés : ils sont audités et copiés dans `role_state` après promotion ;
  8. une seule définition des classes d'entrées et de la fenêtre écoulée (`ppp_entry_class()`, `ppp_window_elapsed()`) pour le hook, l'éviction et le worker.
- (code-review) S1 — `_apply_valid_until()` en mode `unblock` écrit `infinity` (borné seulement par `rotation_pair.previous_valid_until`) et non plus `grace_until` : avec `manage_valid_until = off`, plus personne ne relevait cette nouvelle borne une fois passée et le rôle finissait bloqué définitivement. Test : `70_maintenance` (`unblocked_infinity`).
- (code-review) S2 — `_is_exempt()` découpe `exempt_roles` avec `_split_identifiers()`, réécriture en PL/pgSQL de `SplitIdentifierString()` (noms non quotés en minuscules ASCII, `"quotés"` tels quels, `""` = un guillemet, espaces ignorés, troncature à 63 octets, NULL si la syntaxe est invalide) : SQL et C donnent le même résultat. Test : `90_privileges` (découpage, puis comparaison `_is_exempt()` / hook sur trois rôles après `ALTER SYSTEM SET` + `pg_reload_conf()`). *Remplacé* : `_is_exempt()` est une fonction C, voir (code-review 2) R3.
- (code-review) S3 — `run_maintenance()` étape a0 : seules les lignes dont l'OID n'existe plus dans `pg_authid` (et, pour `password_history`, `role_oid IS NULL`) sont rattachées par nom ; les renommages suivent toujours l'OID (conditions `NOT EXISTS` sur l'ancien nom supprimées). Un renommage suivi de la création d'un rôle portant l'ancien nom ne transfère plus verrou, profil ni historique. Limite assumée : un rôle supprimé puis recréé sous le même nom entre deux passes ne se distingue pas d'une restauration et hérite des lignes. Test : `70_maintenance` (`regress_alice` → `regress_bob`).
- (code-review) S4 — rôle exempté : `rotate_password()` et `switch_rotation_pair()` (rôle devenu actif) appellent `_apply_valid_until()` en mode `unblock` (seule une borne passée est relevée, à `infinity`) : `run_maintenance()` étape d ignore ces rôles et ne resynchroniserait jamais un `VALID UNTIL` posé par `force` (*complété* : l'étape d garde désormais les rôles exemptés en mode `unblock`, voir (code-review 2) R2). La borne de l'ancien rôle d'une paire reste posée (`force`) : elle est l'objet même du basculement et le basculement suivant la relève. Test : `90_privileges` (`exempt_rotate_*`).
- (code-review) S5 — `switch_rotation_pair()` applique au nouveau rôle actif la même règle que `rotate_password()` : `force` si `manage_valid_until = on` et rôle non exempté, `unblock` sinon. Test : `70_maintenance` (`switch_no_valid_until`).
- (code-review) S6 — plus aucun droit à `PUBLIC` : ni `USAGE` sur le schéma (inutile : le hook tourne en `BOOTSTRAP_SUPERUSERID`, les vues et fonctions `SECURITY DEFINER` appartiennent au superutilisateur), ni `EXECUTE` sur `effective_profile()` (accordée à `pass_policy_viewer` et `pass_policy_admin`), `audit()` (`pass_policy_admin`) ou `record_password_change()` (personne). La garde `_in_password_hook()` est conservée en défense en profondeur. Les refus de `90_privileges` gardent le SQLSTATE `42501` (« permission denied for schema » au lieu du contrôle interne). Test ajouté : un utilisateur ordinaire change son propre mot de passe (politique appliquée, historique, `role_state` et audit enregistrés) et `has_*_privilege` pour PUBLIC/viewer/admin.
- (code-review) S7 — troncature de l'historique factorisée dans `_trim_history(oid)` (profil effectif lu dans `_role_effective_profile`), appelée par `_record_password_change()` et par l'étape b de `run_maintenance()`.
- (code-review) S8 — `rotate_password()` et `switch_rotation_pair()` ne font plus `UPDATE role_state SET must_change = false` : `_record_password_change()` (hook ou `_ensure_recorded()`) le fait déjà.
- (code-review) S9 — `unassign_profile()` d'un rôle disparu ne recalcule plus `role_state` (l'appel `_refresh_role_state(NULL)` recalculait tous les rôles).
- (code-review) C1 — nouvelle fonction `ppp_extension_state(Oid *nspowner)` (`pg_pass_policy.h`, ajout) à trois états : absente (comportement inchangé : `PPP-003` ou WARNING), installée et fiable, présente mais non fiable (schéma `pass_policy` absent, extension ailleurs, propriétaire non superutilisateur). Dans ce dernier cas le hook, `check_password()` et `generate_password()` lèvent `PPP-004` (« pg_pass_policy schema is not trusted », SQLSTATE `55000`, DETAIL sur le propriétaire) au lieu d'accepter le mot de passe sans politique. `ppp_extension_installed()` garde sa signature (= état fiable) pour le worker. Test : `90_privileges` (`ALTER SCHEMA pass_policy OWNER TO regress_user`).
- (code-review) C2 — le hook, `check_password()` et `generate_password()` tournent entièrement sous la garde GUC de `ppp_spi_begin()` ; toute ERROR qui en sort est rattrapée puis relancée avec `hide_stmt` et `hide_ctx` (`ppp_rethrow_hidden()`). La garde seule ne suffisait pas : une ERROR est écrite dans le log par le gestionnaire le plus externe, après restauration des GUC, avec la ligne `STATEMENT` qui contient le mot de passe (`ppp_require_schema()`, `get_role_oid()`, `encrypt_password()`, erreurs SPI…). Test : `notify.sh` (`check_password()` dans une base sans l'extension, mot de passe absent de `server.log`).
- (code-review) C3 — `min_age` et l'historique cherchent par OID seulement pour un rôle existant ; pour un rôle pas encore créé (`CREATE ROLE … PASSWORD`), par nom parmi les seules lignes `password_history.role_oid IS NULL`. Les lignes périmées d'un rôle supprimé ne provoquent plus de faux `PPP-030` ni ne ressuscitent ses anciens vérificateurs pour un rôle recréé. Test : `30_history` (`regress_reborn`, `regress_born`). *Complété* pour un rôle existant : les lignes `role_oid IS NULL` de son nom sont aussi prises en compte, voir (code-review 2) R1.
- (code-review) C4 — `check_password()` ne contrôle `min_age` que si l'appelant peut consulter l'historique (superutilisateur ou le rôle lui-même) : sinon `PPP-030` renseignait sur la date du dernier changement d'un autre rôle. Test : `90_privileges` (`admin_check_other`).
- (code-review) C5 — dictionnaire : colonne générée `word_sha256` (index unique) et requête `SELECT 1 … WHERE word_sha256 = $1` avec le SHA-256 du mot de passe en minuscules calculé en C. Le digest passe par `DirectFunctionCall1(sha256_bytea, …)` (fonction SQL `sha256()`, même signature fmgr de PG 11 à 18) plutôt que par `common/cryptohash.h`, dont la signature n'a pu être vérifiée que sur 16.4 et 17beta1 (absent de 13.2). L'expression `sha256(convert_to(word, 'UTF8'))` proposée n'est pas utilisable : `convert_to()` est STABLE (interdit dans une colonne générée) ; `textsend()` convertit vers l'encodage du client. Retenu : `sha256(decode(replace(word, '\', '\\'), 'escape'))`, IMMUTABLE, octets bruts dans l'encodage du serveur, comme `ppp_lower()` côté C. Le mot de passe en clair ne transite toujours pas ; le digest est un paramètre lié d'une requête SPI, que ni `log_statement` ni `log_parameter_max_length` ne journalisent (ils ne visent que l'instruction de premier niveau), auto_explain étant neutralisé par `ppp_spi_begin()`. Le tampon d'entrée et le digest sont effacés. `load_dictionary()` et le trigger de normalisation sont inchangés (la colonne est calculée après les triggers BEFORE). Test : `20_complexity` (mot avec `\`, cohérence des digests).
- (code-review) C6 — une seule session SPI élevée par point d'entrée : le hook (ouverte après le test `enabled`/exempté, puis, depuis (code-review 2) R5, seulement si l'extension est installée et fiable ; fermée à la fin ; en cas d'erreur, identité restaurée et relance masquée, GUC et connexion SPI libérés par l'abandon de la (sous-)transaction), `check_password()` et `generate_password()`. `superuser()` et `GetUserId()` de l'appelant sont lus avant l'élévation et passés aux fonctions de contrôle (`caller_is_super`). L'audit `password_rejected` s'exécute dans une sous-transaction de cette même session. Les chaînes du profil et les résultats sont alloués dans le contexte mémoire antérieur à `SPI_connect()` (`pppSpiState.outer_cxt`).
- (code-review) C7 — wrapper `ppp_schema_exists()` supprimé ; commentaire « Wipe memory… » replacé au-dessus de `ppp_secure_zero()`.
- (code-review) C8 — DETAIL de `PPP-031` : « The password must differ from the last %d passwords (current one included). » (§3.1 aligné).
- (code-review) C9 — alphabet complet de `generate_password()` en constante statique (`ppp_alpha_all`), plus de `psprintf` à chaque essai ; le tampon est aussi effacé si une ERROR survient pendant la génération.
- (code-review) C10 — `exempt_roles` découpé une fois par un assign hook dans un contexte mémoire privé (`ppp_exempt_cxt`), `ppp_role_is_exempt()` ne fait plus que des `strcmp`. Le pointeur `extra` n'a pas été retenu : il doit être alloué par `malloc()` jusqu'à PG 15 et par `guc_malloc()` à partir de PG 16 (`guc_free()` fait un `pfree()`), test de version que seul `compat.h` peut faire (§6.5) et que ce lot ne pouvait pas modifier. Allocations en `MCXT_ALLOC_NO_OOM` ; en cas d'échec, `ppp_role_is_exempt()` repasse au découpage à chaque appel. Sémantique inchangée (S2).
- (code-review 2) R1 — historique d'un rôle existant : `WHERE (role_oid = $oid OR (role_oid IS NULL AND role_name = $nom))`. Les lignes sans OID écrites par `CREATE ROLE … PASSWORD` étaient ignorées jusqu'au `run_maintenance()` suivant : `CREATE ROLE u PASSWORD 'A'`, `ALTER ROLE u PASSWORD 'B'`, `ALTER ROLE u PASSWORD 'A'` était accepté. Même examen pour `min_age` : faute de ligne `role_state` (créée par la maintenance seulement), la date de la dernière ligne sans OID du même nom est retenue (`GREATEST(role_state.password_changed_at, …)`) ; `min_age` ne dépend donc plus du passage de la maintenance (un rôle créé avec un mot de passe ne peut pas le changer lui-même avant `min_age`, comme après la maintenance). Les lignes sans OID d'un rôle supprimé puis recréé sous le même nom avant la maintenance sont comparées aussi (limite déjà assumée pour `CREATE ROLE`, voir C3). Test : `30_history` (`regress_fresh`, `regress_fresh2`, sans `run_maintenance()` : `worker_interval = 0`).
- (code-review 2) R2 — `run_maintenance()` étape d garde les rôles exemptés, en mode `unblock` seulement (même règle que `rotate_password()`) : `WHERE a.rolcanlogin AND ((manage AND NOT exempt) OR (NOT must_change AND rolvaliduntil IS NOT DISTINCT FROM valid_until_synced))`, `sync` seulement si `manage_valid_until = on` et rôle non exempté. Un `VALID UNTIL` passé posé par `expire_password()` n'était jamais levé pour un rôle exempté dont le mot de passe est changé par un `ALTER ROLE` direct (le hook ne l'enregistre pas, l'étape b le réconcilie). L'étape e (alertes, `password_expired`) ignore toujours les rôles exemptés. Test : `90_privileges` (`exempt_direct_unblocked`).
- (code-review 2) R3 — `_split_identifiers()` (réécriture PL/pgSQL de `SplitIdentifierString()`) est supprimée ; `_is_exempt(text) RETURNS bool` devient une fonction **C** (`ppp_is_exempt`, `pg_pass_policy.c`, `STABLE STRICT`) qui appelle `ppp_role_is_exempt()` : une seule implémentation pour le SQL et les hooks. Pas de `_exempt_list()` : inutile pour R4. Test : `90_privileges` (`_is_exempt()` sur `a`, ` a `, `A`, `postgres`/`Postgres`, `App User`, `x"y`… après `ALTER SYSTEM SET` + `pg_reload_conf()`, attente bornée à 5 s faite d'une instruction par tour avec `\gexec` : le backend ne relit la configuration qu'entre deux instructions, une boucle PL/pgSQL ne verrait jamais la nouvelle valeur).
- (code-review 2) R4 — `run_maintenance()` évalue `_is_exempt()` une seule fois par rôle LOGIN et par passe (tableau `v_exempt oid[]` calculé avant l'étape d, utilisé par les étapes d et e).
- (code-review 2) R5 — le hook lit l'état de l'extension (`ppp_extension_state()`, catalogues seulement) **avant** `ppp_spi_begin()` : absente (WARNING / `PPP-003`) et non fiable (`PPP-004`) sont traitées sans session SPI élevée, ouverte seulement pour l'état fiable. `check_password()` et `generate_password()` font de même (contrôle avant l'élévation).
- (code-review 2) R6 — `switch` unique : `ppp_require_extension(bool absent_is_error)` renvoie l'état (`PPP_EXT_TRUSTED` ou `PPP_EXT_ABSENT`), lève `PPP-004` pour l'état non fiable, l'ERROR « not installed » pour l'état absent si `absent_is_error` (fonctions SQL), et une ERROR interne (`elog`) pour un état inconnu (`default`). Le traitement de l'état absent par le hook est isolé dans `ppp_extension_absent()`.
- (code-review 2) X1 — `v_role_status` expose `role_oid` (dernière colonne, `v_expiring` en hérite) ; `v_locked` joint `role_state` par OID et non plus par `role_name`, périmé après `ALTER ROLE … RENAME` jusqu'à la maintenance (le verrou s'affichait sans origine ni motif). Les clients `cli/` et `web/` lisent des colonnes nommées : compatibles. Test : `70_maintenance` (`regress_alice` → `regress_bob`, avant `run_maintenance()`).
- (code-review 2) X2 — `lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)` renvoie `timestamptz` : le `locked_until` posé (`infinity` pour un verrou manuel). `cli/src` et `web/app` appellent la fonction sans lire son résultat (`execute`) : compatibles. Tests : `60_lock_unlock` (`= 'infinity'`, `= now() + interval '1 second'`), `70_maintenance`.
- (code-review 2) X3 — `lock_role()`, `unlock_role()`, `expire_password()` et `_ensure_state()` rafraîchissent `role_state.role_name` (nom courant lu dans `pg_authid`). L'étape f de `run_maintenance()` (déverrouillage automatique) prend le nom dans `pg_authid` (jointure par OID) pour `_shmem('unlock')`, l'audit `role_unlocked` et la ligne `role_state` ; l'étape a0 renommait déjà `role_state.role_name` plus tôt dans la même passe, la jointure rend l'étape f indépendante de cet ordre. Test : `70_maintenance` (`regress_ren1` → `regress_ren4`, puis `regress_carol` verrouillé 3 s, renommé `regress_dave`, verrou réinjecté par le worker sous le nouveau nom, levé par `run_maintenance()` : shmem, audit et `role_state` au nom `regress_dave`).
- (code-review 3) `assign_profile()` et `unassign_profile()` appliquent `_require_target_allowed()` comme les autres actions : un admin non superutilisateur ne peut pas changer le profil d'un rôle privilégié.
- (revue finale) Sécurité, PG ≤ 15 — `_require_target_allowed()` : la branche transitive (rôles dont la cible est membre) ne testait pas `CREATEROLE`, alors que la branche directe le faisait ; un admin non superutilisateur pouvait créer une paire sur un groupe membre d'un rôle `CREATEROLE`, puis `SET ROLE` vers lui et s'accorder `pg_execute_server_program`. Prédicat unique `_is_privileged(oid) RETURNS bool` (`STABLE`), appliqué à la cible et à chacun de ses ancêtres (§4). Le filtre d'affichage `_PRIVILEGED_ROLE` de `web/app/db.py`, copie de l'ancien prédicat, a le même oubli (simple affichage : l'extension refuse et l'erreur est montrée). Test : `90_privileges` (`createrole_rule`, `createrole_member_rule`, `createrole_group_rule`, écrits indépendamment de la version).
- (revue finale) E1 — l'oracle `CREATE ROLE <existant> PASSWORD …` (« already exists » contre `PPP-031`) n'existe pas : `CreateRole()` teste l'existence (42710) et `AlterRole()` les droits **avant** d'appeler `check_password_hook` (vérifié dans les sources 13.2, 16.4 et 17beta1). Défense en profondeur ajoutée tout de même : pour un rôle existant, historique et `min_age` ne sont contrôlés que si l'appelant peut changer ce mot de passe (`PPP_MAY_SET_PASSWORD_OF()`, `compat.h`, §6.2 étape 5), sinon sautés en silence ; la complexité est toujours contrôlée (elle ne renseigne que sur le candidat). Test : `90_privileges` (`create_existing_current`, `create_existing_weak` : 42710 ; `alter_other_current` : 42501 sur PG ≥ 16, `PPP-031` sur PG ≤ 15 où `CREATEROLE` peut de toute façon changer ce mot de passe).
- (revue finale) E2 — `lock_duration` < 1 s devenait 0 après `::int4` (`locked_until = now`, verrou jamais effectif) et un `failure_window` < 1 s « pas de fenêtre ». Contraintes `CHECK (lock_duration >= '1 second')` et `CHECK (failure_window = '0' OR failure_window >= '1 second')` ; le worker borne en plus à `[1, 2^31 − 1]` (`PPP_SQL_WINDOW_SECS`, `PPP_SQL_LOCK_SECS`, `CASE` explicite : `GREATEST()` ignore les NULL et transformerait le −1 du verrou manuel). Test : `10_profile`.
- (revue finale) E3 — `PPP_OP_UNLOCK` effaçait `lock_pending_audit` : un verrou automatique levé par `unlock_role()` avant le passage du worker n'était jamais audité. Nouveau champ `pppRoleEntry.audit_locked_until` (verrou à journaliser) ; `lock_pending_audit` n'est plus effacé par le déverrouillage, par `lock_role()` ni par le rechargement ; le worker écrit `role_locked` avec cette valeur et ne la recopie dans `role_state` que si le verrou est toujours en place (§6.3). Limite inchangée : un second verrou automatique posé avant le passage du worker remplace le premier, qui n'est pas audité. Test : `hashfull.sh` (`regress_e3` : verrou auto, `unlock_role()`, tour du worker → `role_locked` et `role_unlocked`, `role_state` non verrouillé).
- (revue finale) E4 — le hook d'authentification appelle le hook précédent avant de lever le FATAL « locked » (après `LWLockRelease`), et non plus après (code jamais atteint pour un rôle verrouillé).
- (revue finale) E5 — annulation de `ppp_apply_lock_ops()` faute de place : l'entrée évincée pour créer un verrou annulé était perdue (compteur d'échecs, échecs non audités). `ppp_enter_role()` copie la victime dans `pppEviction.victim` et l'annulation la réinsère (ordre inverse, la place libérée par le retrait de l'entrée créée garantit l'insertion). Choisi plutôt qu'un décompte préalable des places : restitution exacte, sans second parcours du hash. Test : `hashfull.sh` (verrou de A puis B avec une seule place évincable : ERROR 53400, compteur de `regress_l2` intact, verrou au 5e échec).
- (revue finale) E6 — `_shmem()` ne dégrade plus en WARNING les erreurs de `'lock'` et `'unlock'` : `lock_role()` validait `role_state` et l'audit alors que la shmem n'avait rien reçu (bibliothèque retirée de `shared_preload_libraries`, par exemple : fail-open). `unlock_role()` échoue aussi (cohérence `role_state`/shmem ; l'étape f de `run_maintenance()` également). `'reload'` et `'reset'` gardent le WARNING. Test : `lockout.sh` (redémarrage avec `shared_preload_libraries = ''`) ; impossible en pg_regress, dont l'instance précharge toujours la bibliothèque.
- (revue finale) E7 — valeurs par défaut du verrouillage (5 / 900 / 1800) définies une seule fois (`PPP_DEFAULT_*`, `pg_pass_policy.h`) et initialisées à un seul endroit (`ppp_shmem_startup()`, avec la première demande de rechargement) ; `ppp_lockout_shmem_init()` ne crée plus que le hash.
- (revue finale) E8 — `ppp_make_key()` exportée (`pg_pass_policy.h`) et utilisée par `ppp_ack_pending()` ; `ppp_text_datum()` supprimée.
- (revue finale) E9 — `_audit()` n'appelle plus `worker_status()` (LWLock, tuplestore, sous-transaction du bloc `EXCEPTION`) pour chaque ligne : nouvelle fonction **C** `_worker_pid() RETURNS int` (`ppp_worker_pid`, lecture de `ppp_shared->worker_pid` sous LWLock partagé, NULL si le worker ne tourne pas) comparée à `pg_backend_pid()`. Sans bibliothèque préchargée, `_audit()` lève désormais l'erreur de chargement au lieu de l'ignorer (comme toute fonction C de l'extension).
- (revue finale) E10 — couvert par le constat de sécurité (`_is_privileged()`).
- (revue finale 2) F1 — sécurité : le hook comptait tout `STATUS_ERROR`, quelle que soit la méthode. Vérification dans `auth.c` (13.2, 16.4, 17beta1) : `uaReject` et `uaImplicitReject` lèvent leur FATAL dans le `switch` de `ClientAuthentication()`, **avant** l'appel du hook, donc les connexions refusées par `pg_hba.conf` n'étaient en fait pas comptées ; en revanche `peer`, `ident`, `cert`, `gss` et `sspi` échouent avec `STATUS_ERROR` sans qu'aucun mot de passe n'ait été présenté (un client qui contrôle son identd pouvait verrouiller n'importe quel rôle par son nom). Seuls `password`, `md5`, `scram-sha-256`, `ldap`, `pam`, `radius`, `bsd` comptent désormais (`ppp_auth_method_checks_secret()`, `port->hba->auth_method`, `port->hba` vérifié non NULL ; enum `UserAuth` identique dans 13.2, 16.4 et 17beta1, `oauth` de PG 18 non compté) ; le refus d'un rôle verrouillé reste appliqué pour toute méthode. Pas de shim `compat.h` nécessaire. Test : `lockout.sh` (ligne `ident` pour `regress_ident` sans identd, lignes `reject` par rôle et par base, 6 tentatives chacune : `failed_attempts()` vide, compteur de `regress_lock` inchangé, rôles non verrouillés ; le test échoue si l'on compte tous les `STATUS_ERROR`).
- (revue finale 2) F2 — `run_maintenance()` prend `pg_advisory_xact_lock(hashtext('pg_pass_policy.run_maintenance'))` après `_require_admin()` : deux passes concurrentes (worker et pg_cron, ou appel manuel) sont sérialisées ; verrou de transaction, relâché au COMMIT/ROLLBACK, réentrant dans une même transaction. Test : `70_maintenance` (deux passes dans une transaction, verrou tenu puis relâché au COMMIT, troisième passe).
- (revue finale 2) F3 — une entrée au verrou expiré et à l'audit `role_locked` en attente restait `KEEP` tant que le worker n'avait pas écrit la ligne : jamais évincable sur un standby ni avec un worker qui ne peut pas écrire. Elle est désormais classée sur son compteur quand le verrou a pris fin depuis plus de 24 h (`PPP_STALE_AUDIT_SECS`) ou dès son expiration sur un standby (`RecoveryInProgress()`, lu avant le LWLock et passé à `ppp_entry_class()` / `ppp_enter_role()`) ; éviction journalisée en LOG (`pppEviction.lost_lock_audit`), jamais purgée par le worker lui-même. Perte bornée documentée (§6.3). Test : `standby.sh` (standby à `max_tracked_roles = 16`, 15 vrais rôles verrouillés 1 s puis expirés, le 16e rôle est compté et verrouillé, LOG présent ; échoue sans la correction).
- (revue finale 2) F4 — `PPP_OP_UNLOCK` effaçait au COMMIT tout verrou, y compris un verrou automatique plus récent. Horodatage `lock_set_at` (pose, hook et PRE_COMMIT) et `queued_at` (demande) ; au COMMIT, un verrou actif n'est levé que s'il est `lock_from_state` ou si `lock_set_at <= queued_at`, sinon il est conservé (LOG). Cela ne suffisait pas pour l'étape f de `run_maintenance()` : le nouveau verrou peut être posé **avant** la passe (la shmem a déjà oublié le verrou expiré que `role_state` porte encore), donc avant `queued_at`. D'où `shmem_unlock_role(role, expired_only => true)` (`_shmem('unlock_expired')`), qui ne lève jamais un verrou actif. Test : `lockout.sh` (worker à 600 s, verrou automatique expiré dans `role_state`, 5 nouveaux échecs, `run_maintenance()` manuel : `role_unlocked` écrit, rôle toujours verrouillé, verrou recopié dans `role_state` au tour suivant ; échoue avec l'ancien `_shmem('unlock')`).
- (revue finale 2) F5 — les échecs en attente des noms inexistants produisaient une ligne `auth_failed` et un NOTIFY par nom inventé et par tour. Une seule ligne agrégée par tour, `role_name` NULL, `details` `{"unknown_roles", "attempts", "pseudo_locks", "last_failure_at", "source"}` ; les pseudo-verrous des noms inexistants y sont comptés au lieu d'une ligne `role_locked` chacun (choix fait ici : même problème de volume). Test : `lockout.sh` (3 noms × 2 échecs → une ligne `1:3/6`, aucune ligne au nom des fantômes).
- (revue finale 2) F6 — logique « verrou expiré » commune au hook et au worker : `ppp_expire_lock(entry, now, check_inflight)` (`pg_pass_policy.h`). Écart résorbé : le worker remet désormais aussi à zéro le compteur de l'épisode expiré quand l'audit est encore en attente, comme le hook le faisait déjà.
- (revue finale 2) F7 — `_require_target_allowed()` ne parcourt plus tout `pg_authid` avec `_is_privileged()` + `pg_has_role()` par rôle : `WITH RECURSIVE` sur `pg_auth_members` depuis la cible (toutes les attributions, sans tenir compte d'`INHERIT`/`SET`, comme `is_member_of_role()` / `roles_is_member_of(ROLERECURSE_MEMBERS)` de 16.4), plus l'appartenance implicite du propriétaire de la base à `pg_database_owner` que `roles_is_member_of()` ajoute ; `_is_privileged()` n'est appliqué qu'aux ancêtres. `pg_database_owner` ne peut être membre d'aucun rôle en 16.4 et 17beta1 (« cannot be a member of any role »), la branche implicite est gardée pour rester identique à `pg_has_role()` sur PG 14 et 15 (non vérifié dans leurs sources). Équivalence vérifiée sur une instance 16.4 (ancien et nouveau prédicat sur tous les rôles, dont grants `INHERIT FALSE` et `SET FALSE`, chaînes et propriétaire de base) ; `90_privileges` inchangé et vert.
- (revue finale 2) F8 — `ppp_begin_materialize(fcinfo, &tupdesc, &tupstore, expected_natts)` (`pg_pass_policy.c`, exportée) remplace le code SRF dupliqué de `failed_attempts()` et `worker_status()`.
- (revue finale 2) F9 — `check_password()` est `STRICT` : test `PG_ARGISNULL` retiré (code mort), de même dans `shmem_unlock_role()` et `shmem_reset_failures()`, `STRICT` aussi ; `shmem_lock_role()` (non `STRICT`, `until` NULL = manuel) et `generate_password()` gardent les leurs.
