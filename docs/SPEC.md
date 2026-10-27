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
| history_count | int | 5 | N derniers vérificateurs comparés (0 = désactivé) |
| history_days | int | 365 | âge max des entrées comparées |
| max_age | interval NULL | '90 days' | NULL = n'expire jamais |
| min_age | interval | '1 day' | refuse un second changement dans l'intervalle (sauf superutilisateur) |
| grace_period | interval | '7 days' | VALID UNTIL = changed_at + max_age + grace_period |
| warn_before | interval | '14 days' | alerte (audit + NOTIFY) quand expires_at − now() < warn_before |
| max_failures | int | 5 | 0 = verrouillage désactivé |
| failure_window | interval | '15 minutes' | fenêtre de comptage des échecs |
| lock_duration | interval NULL | '30 minutes' | NULL = déverrouillage manuel uniquement |
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

`word text PK` (stocké en minuscules). L'extension charge ~200 mots de passe
courants (top listes publiques, « password », « postgres », « admin »,
« qwerty », suites de clavier…). Fonction `load_dictionary(words text[])`.

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
| `expire_password(role name)` | void | `must_change = true`, `VALID UNTIL now()`, audit |
| `lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)` | void | NULL = manuel ; met à jour `role_state` + `shmem_lock_role` |
| `unlock_role(role name)` | void | `role_state` + `shmem_unlock_role` + `shmem_reset_failures` |
| `record_password_change(role text, verifier text)` | void | appelée **par le hook C** via SPI après acceptation ; insère l'historique, tronque à `history_count`, met à jour `role_state`, audit `password_changed` |
| `run_maintenance()` | TABLE(action text, role_name text, details jsonb) | ce que fait le worker (appelable par pg_cron) : sync VALID UNTIL, alertes, expirations, déverrouillages auto, purge rôles disparus, réconciliation `pg_authid.rolpassword` vs historique, `shmem_reload()` |
| `create_rotation_pair(pair text, role_a name, role_b name, group_role name)` | void | crée les rôles manquants (`LOGIN`, membres du groupe) |
| `switch_rotation_pair(pair text, length int DEFAULT 24)` | TABLE(active_role text, password text, previous_role text, previous_valid_until timestamptz) | |
| `purge_audit(older_than interval DEFAULT '365 days')` | bigint | |
| `load_dictionary(words text[])` | int | |
| `audit(event_type text, role_name text, details jsonb DEFAULT '{}')` | void | insère + `pg_notify(current_setting('pg_pass_policy.notify_channel'), json)` ; utilisée par toutes les autres |
| `failed_attempts()` | TABLE(role_name text, failed_count int, first_failure_at timestamptz, last_failure_at timestamptz, locked_until timestamptz) | **C** — lit la shmem |
| `shmem_reload()` | void | **C** — demande, à la validation de la transaction appelante, au worker de recharger les paramètres de verrouillage dans la shmem (un ROLLBACK annule la demande) |
| `shmem_lock_role(role text, until timestamptz)` | void | **C** — `until` NULL = manuel (DT_NOEND) ; écriture shmem différée au COMMIT (annulée par ROLLBACK / ROLLBACK TO SAVEPOINT) |
| `shmem_unlock_role(role text)` | void | **C** — différée au COMMIT |
| `shmem_reset_failures(role text)` | void | **C** — différée au COMMIT |
| `worker_status()` | TABLE(pid int, last_run timestamptz, last_reload timestamptz, tracked_roles int) | **C** |

Règles communes à l'API :

- `record_password_change()` et `audit()` sont `GRANT EXECUTE TO PUBLIC` (le
  hook C les appelle dans la session de n'importe quel utilisateur), mais elles
  refusent tout appel **hors du hook** (`pass_policy._in_password_hook()` =
  false) dès que `session_user` n'est ni superutilisateur ni membre de
  `pass_policy_admin` : SQLSTATE `42501` (`insufficient_privilege`) ;
- un membre de `pass_policy_admin` qui n'est pas superutilisateur ne peut pas
  viser un rôle **privilégié** avec `rotate_password`, `expire_password`,
  `lock_role`, `unlock_role`, `create_rotation_pair` (rôles de la paire déjà
  existants **et** `group_role`, car le `GRANT group_role TO role_a/role_b`
  est exécuté en `SECURITY DEFINER`) ni `switch_rotation_pair`
  (`_require_target_allowed()`, SQLSTATE `42501`). Est privilégié un rôle qui
  a `SUPERUSER`, `REPLICATION` ou `BYPASSRLS`, un rôle prédéfini `pg_*`
  (`pg_execute_server_program`, `pg_write_server_files`… ; `pg_database_owner`
  est exclu : tout propriétaire de base en est membre implicite et il
  n'apporte rien au-delà de la propriété), un rôle membre, même indirect,
  d'un tel rôle (`SET ROLE` / `INHERIT` en donnent les privilèges), ou, sur
  PostgreSQL ≤ 15, un rôle `CREATEROLE` ;
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
  grace_until, days_left, locked_until, failed_count, status)` avec `status` ∈
  `ok | warning | grace | expired | locked | never_expires | unknown` ;
  `unknown` = date de changement inconnue (rôle antérieur à l'extension) ;
- `v_expiring` : status in (warning, grace, expired) ;
- `v_locked` ;
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
| exempt_roles | string | '' | SIGHUP | liste séparée par virgules exemptée de la politique et du verrouillage |
| superuser_bypass | bool | off | SIGHUP | si on : les superutilisateurs ne sont pas soumis à la complexité |
| require_scram | bool | on | SIGHUP | refuse MD5 (`password_encryption = md5`) |
| enforce_database | bool | on | SIGHUP | hors de `pg_pass_policy.database`, `ALTER ROLE … PASSWORD` est refusé (sinon seulement ignoré avec WARNING) |

PG ≥ 15 : `MarkGUCPrefixReserved("pg_pass_policy")`, sinon
`EmitWarningsOnPlaceholders`.

## 6. Contrat C (voir `src/pg_pass_policy.h`)

### 6.1 Propriétaires

| fichier | propriétaire | contenu |
|---|---|---|
| `pg_pass_policy.c` | agent « core » | `_PG_init`, GUC, `shmem_request_hook`/`RequestAddinShmemSpace`, `shmem_startup_hook` → `ppp_lockout_shmem_init()`, enregistrement du worker, `ppp_role_is_exempt`, `ppp_worker_status` |
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
1. si `!ppp_enabled` ou rôle exempt → chaîner au hook précédent et sortir ;
2. charger le profil effectif via SPI : `SELECT * FROM pass_policy.effective_profile($1)` (si le schéma n'existe pas dans cette base → **ne rien bloquer**, juste `ereport(WARNING)` une fois par session : l'extension n'est installée que dans `pg_pass_policy.database` ; **ATTENTION** : le hook s'exécute dans la base courante de la session, pas dans `pg_pass_policy.database`. Décision : la politique n'est appliquée que lorsque `current_database() = ppp_database` **ou** si la table est accessible localement ; en dehors, refuser `ALTER ROLE … PASSWORD` (et `CREATE ROLE … PASSWORD`) avec l'ERROR `PPP-003` (« password changes must be made while connected to database X ») si `ppp_enabled`. Ce comportement est contrôlé par le GUC `pg_pass_policy.enforce_database` (bool, défaut on ; off = simple WARNING, une fois par session) ;
3. si `password_type != PASSWORD_TYPE_PLAINTEXT` : `reject_prehashed` → ERROR `PPP-001` ; vérificateur MD5 et `pg_pass_policy.require_scram` → ERROR `PPP-002` ; sinon enregistrer sans vérification de complexité (seul `min_age` est contrôlé). Pour un mot de passe en clair, `PPP-002` est aussi levé si `require_scram` et `password_encryption = md5` ;
4. vérifications de complexité (ordre et codes) : `PPP-010` longueur min, `PPP-011` longueur max, `PPP-012` classes (min_classes), `PPP-013` min_lower, `PPP-014` min_upper, `PPP-015` min_digit, `PPP-016` min_special, `PPP-017` contient le nom du rôle, `PPP-018` dictionnaire, `PPP-019` répétitions, `PPP-020` caractères non imprimables / espace en début-fin. Codes hors complexité : `PPP-001` pré-haché refusé, `PPP-002` MD5 refusé par `require_scram`, `PPP-003` changement hors de `pg_pass_policy.database` ;
5. `min_age` : `PPP-030` si `now() - password_changed_at < min_age` (sauf superutilisateur appelant) ;
6. historique : pour chaque vérificateur SCRAM des `history_count` derniers (et plus récents que `history_days`), `scram_verify_plain_password(username, password, verifier)` → `PPP-031` si égal ; vérificateurs MD5 : comparés via `pg_md5_encrypt` ;
7. calcul du nouveau vérificateur : `encrypt_password(PASSWORD_TYPE_SCRAM_SHA_256, username, shadow_pass)` (PG 14-18 : `libpq/crypt.h`) ; si `password_type == PLAINTEXT` ; sinon `shadow_pass` tel quel ;
8. SPI `SELECT pass_policy.record_password_change($1, $2)` ;
9. chaîner au hook précédent.

Refus : `ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD), errmsg("PPP-0xx: …"), errdetail(…), errhint(…)))`. Le mot de passe n'apparaît **jamais** dans un message, un log ou l'audit. Un refus est journalisé (`password_rejected`, details = code) via SPI dans une sous-transaction qui ne doit pas masquer l'erreur principale (ou simplement `ereport(LOG)` si l'audit échoue).

Les caractères sont comptés en points de code UTF-8 (`pg_mblen`) ; les classes : minuscule / majuscule (`pg_wchar` + `iswlower/iswupper` ou ASCII suffisent + tout caractère non-ASCII compte comme « special »), chiffre ASCII, special = tout le reste imprimable.

### 6.3 Hook d'authentification et shmem (`lockout.c`)

Le hook s'exécute dans le backend **avant** l'initialisation complète : **aucun
SPI, aucun accès catalogue**. Toute information vient de la shmem, remplie par
le worker.

```
static void ppp_client_auth_hook(Port *port, int status);
```

1. chaîner d'abord au hook précédent (sauf si on va refuser) ;
2. si `!ppp_enabled` ou rôle exempt → sortir ;
3. `LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE)` ; chercher `port->user_name` dans `ppp_role_hash` ; si absent **et** `status != STATUS_OK` → créer avec les paramètres par défaut (`ppp_shared->default_*`) ; si le hash est plein → `ereport(LOG)` et sortir sans bloquer ;
4. si `locked_until > now` (ou `DT_NOEND`) → `ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("role \"%s\" is locked by pg_pass_policy"), errdetail("locked until %s")))` — **même si status == STATUS_OK** ;
5. si `status == STATUS_OK` → `failed_count = 0` ;
6. sinon (`STATUS_ERROR`, `STATUS_EOF` compte comme échec uniquement si `port->user_name` est renseigné) : si `now - first_failure_at > failure_window` → repartir à 0 ; incrémenter ; si `failed_count >= max_failures` et `max_failures > 0` → `locked_until = now + lock_duration` (ou `DT_NOEND`), `lock_pending_audit = true`, `ereport(LOG, "pg_pass_policy: role \"%s\" locked after %d failed attempts")` ;
7. `LWLockRelease`.

Verrou expiré (`locked_until` passé) rencontré par le hook : les compteurs
de l'épisode qui a mené au verrou (`first_failure_at < locked_until`) sont
remis à zéro une seule fois ; `locked_until` n'est effacé que si le worker a
déjà journalisé le verrou (`!lock_pending_audit`), sinon il est conservé
(sans bloquer : `ppp_is_locked()` est faux) et les nouveaux échecs sont
comptés normalement, un nouveau verrou pouvant être posé avant le passage du
worker.

Le worker, à chaque tour, parcourt le hash : écrit les lignes d'audit
`auth_failed` / `role_locked` en attente (`lock_pending_audit`) et copie
`locked_until` vers `role_state` dans une transaction dédiée, puis
**acquitte la shmem seulement après le COMMIT** (`pending_failures`
décrémenté, `lock_pending_audit` effacé si `locked_until` n'a pas changé) ;
dans une seconde transaction il efface les verrous expirés déjà journalisés
(en gardant les échecs comptés après l'expiration), purge les entrées
inactives depuis > 24 h, et recharge les paramètres des profils
(`max_failures`, `failure_window`, `lock_duration`, bornés à 2^31 − 1 s ≈ 68
ans avant conversion en `int4`) pour chaque rôle de `role_profile` + les
valeurs du profil `default` dans `ppp_shared->default_*`.

Au démarrage (`shmem_startup`), le hash est vide ; le worker réinjecte les
verrous manuels/actifs depuis `role_state` lors de son premier tour.

### 6.4 Worker (`worker.c`)

- enregistré dans `_PG_init` via `RegisterBackgroundWorker` (`BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION`, `BgWorkerStart_RecoveryFinished`, `bgw_restart_time = 10`) ;
- `ppp_worker_main` : `BackgroundWorkerInitializeConnection(ppp_database, NULL, 0)` puis `search_path = pg_catalog, pg_temp` (le worker est superutilisateur : toutes ses requêtes sont qualifiées, `pg_catalog.jsonb_build_object` compris), boucle `WaitLatch` avec `ppp_worker_interval` ; sur `reload_requested` ou SIGHUP → tour immédiat ;
- la base `pg_pass_policy.database` doit exister au démarrage : sinon `BackgroundWorkerInitializeConnection` lève le FATAL standard « database "x" does not exist » et le postmaster relance le worker toutes les 10 s (comportement standard des bgworkers, identique à pg_cron) ; le GUC étant `postmaster`, corriger puis redémarrer ;
- chaque tour : `StartTransactionCommand` → si l'extension n'est pas installée (`get_extension_oid("pg_pass_policy", true) == InvalidOid`) → attendre ; sinon `SPI_execute("SELECT * FROM pass_policy.run_maintenance()")`, puis synchronisation shmem (§6.3) ; `CommitTransactionCommand` ;
- ne tourne pas sur un standby (`RecoveryInProgress()` → attendre) ;
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
7. `auto_explain` (`log_nested_statements`) journaliserait les paramètres des requêtes SPI du hook (`record_password_change($1, $2)`, `$2` = vérificateur SCRAM) : `auto_explain.log_min_duration` est mis à -1 (`GUC_ACTION_SAVE` / `set_config(…, true)`) pendant les requêtes SPI du hook, dans `_set_password()` et dans `run_maintenance()`, jusqu'à la sortie de la fonction. `check_password(role, password)` reçoit le mot de passe en argument : la journalisation de la requête englobante (`log_statement`, `log_min_duration_statement` avec `log_parameter_max_length = -1` par défaut depuis PG 13, même pour un paramètre lié) n'est pas sous le contrôle de l'extension (README).

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
- `audit()` : `actor = 'worker'` quand `pg_backend_pid()` est le pid du worker (via `worker_status()`), sinon `session_user`.
- Le hook d'authentification ne compte pas `STATUS_EOF` (client parti avant d'envoyer le mot de passe) : seuls les échecs réels (`STATUS_ERROR`) comptent.
- `failure_window` ≤ 0 = pas de fenêtre (les échecs s'additionnent jusqu'au prochain succès).
- Un superutilisateur peut être verrouillé : documenter `pg_pass_policy.exempt_roles = 'postgres'` dans le README.
- `ppp_failed_attempts` est construite avec un tuplestore manuel (même code 14 → 18).
- (agent sql) Nouvelle fonction **C** `pass_policy._in_password_hook() RETURNS bool` (symbole `ppp_in_password_hook`, non STRICT, sans argument) : renvoie `true` uniquement pendant l'exécution du `check_password_hook` de pg_pass_policy dans ce backend (drapeau statique posé/retiré en `PG_TRY/PG_FINALLY` autour des appels SPI du hook). `record_password_change()` et `audit()` sont `GRANT EXECUTE TO PUBLIC` mais refusent l'appel hors hook si `session_user` n'est ni superutilisateur ni membre de `pass_policy_admin` : sinon un utilisateur pourrait repousser sa propre expiration sans changer de mot de passe.
- (agent sql) `role_state.verifier_pending bool NOT NULL DEFAULT false` : posé par `record_password_change()`. Le vérificateur calculé par le hook et celui que PostgreSQL stocke ensuite diffèrent (sel SCRAM différent) ; `run_maintenance()` remplace alors simplement la ligne d'historique par `pg_authid.rolpassword` sans considérer qu'il y a eu un changement hors hook.
- (agent sql) `password_history.role_oid` est NULL pour un `CREATE ROLE … PASSWORD` (le hook s'exécute avant la création du rôle) ; `run_maintenance()` rattache ensuite l'OID par nom et crée `role_state`.
- (agent sql) Les tables sont `REVOKE ALL FROM PUBLIC` et `password_history.verifier` n'est lisible par personne d'autre que le propriétaire : le code C qui lit `dictionary`, `password_history` ou `role_state` (hook, `check_password`) doit le faire avec les droits du propriétaire de l'extension (`SetUserIdAndSecContext`), sauf via `effective_profile()` / `record_password_change()` (SECURITY DEFINER). `USAGE` sur le schéma est accordé à PUBLIC.
- (agent core) Codes ajoutés : `PPP-002` (MD5 refusé par `require_scram`), `PPP-003` (changement de mot de passe hors de `pg_pass_policy.database` avec `enforce_database = on` ; s'applique aussi à `CREATE ROLE`).
- (agent core) Fonction C `pass_policy._in_password_hook()` (`ppp_in_password_hook`) : true seulement pendant le hook (PG_TRY/PG_FINALLY).
- (agent core) Les SPI du hook tournent en `BOOTSTRAP_SUPERUSERID` (`SECURITY_LOCAL_USERID_CHANGE`), `search_path = pg_catalog, pg_temp`, et avec `log_min_error_statement = panic` pour que le `STATEMENT:` contenant le mot de passe ne soit jamais journalisé ; les ereport du hook utilisent `errhidestmt(true)`.
- (agent core) Dictionnaire : seuls les mots de même longueur sont chargés par SPI et comparés en C (le mot de passe ne transite jamais vers le SQL). Correspondance exacte, insensible à la casse.
- (agent core) `PPP-017` ignoré si le nom de rôle fait moins de 3 caractères. `superuser_bypass` ne dispense que de la complexité (jamais de l'historique). `min_age` ignoré si `must_change`.
- (agent core) L'audit `password_rejected` en table est annulé par le rollback de l'ERROR : seule la ligne LOG subsiste. Une file shmem vidée par le worker serait nécessaire pour une trace en table (non implémenté).
- (agent core) `reject_prehashed = true` bloque `\password` de psql et la restauration d'un `pg_dumpall` : documenter `pg_pass_policy.enabled = off` pendant une restauration.
- (finition) Avec `pg_pass_policy.worker_interval = 0`, le worker réveillé par `shmem_reload()` (donc par `assign_profile`, `lock_role`, `run_maintenance`…) ne fait **que** la resynchronisation de la mémoire partagée (`ppp_worker_cycle(run_full = false)`), jamais `run_maintenance()` : en pg_regress seuls les appels explicites à `run_maintenance()` agissent.
- (finition) `CREATE ROLE … PASSWORD` : le hook s'exécute avant que le rôle existe ; l'historique est enregistré avec `role_oid = NULL` et `role_state` n'est créé qu'au `run_maintenance()` suivant (qui rattache l'OID par nom). D'ici là, `v_role_status` affiche `unknown` pour ce rôle.
- (finition) `pg_pass_policy.enabled` et `pg_pass_policy.superuser_bypass` sont de contexte **SIGHUP** : `SET` est refusé, il faut `ALTER SYSTEM SET …` (ou postgresql.conf) puis `pg_reload_conf()`.
- (finition) Un client dont le mot de passe est expiré (`rolvaliduntil` dépassé, posé par le worker ou `expire_password`) reçoit seulement « password authentication failed for user … » ; la cause (« User "x" has an expired password ») n'apparaît que dans le log serveur. Même chose pour un verrou : le client reçoit le FATAL « role "x" is locked by pg_pass_policy ».
- (revue) Le worker acquitte la shmem (`pending_failures`, `lock_pending_audit`) **après** le COMMIT de la transaction « pending audit », distincte de celle du nettoyage/rechargement : une erreur (rechargement, COMMIT) ne perd plus d'audit `auth_failed`/`role_locked` ni de verrou à copier dans `role_state`.
- (revue) `extract(epoch FROM …)` des durées de profil est borné à 2^31 − 1 s (`LEAST(COALESCE(…, -1), 2147483647)::int4`, COALESCE avant LEAST pour garder −1 = manuel) : un `lock_duration` de 100 ans (ou `infinity`) ne casse plus le rechargement.
- (revue) `shmem_reload()`, `shmem_lock_role()`, `shmem_unlock_role()` et `shmem_reset_failures()` n'agissent qu'au COMMIT de la transaction appelante (`RegisterXactCallback` / `RegisterSubXactCallback`, inscrits une fois par backend ; liste en `TopTransactionContext`, `ROLLBACK TO SAVEPOINT` retire les demandes de la sous-transaction) : le signal au worker part quand les lignes sont visibles (sinon il rechargeait l'état antérieur et consommait la demande), et `BEGIN; lock_role(); ROLLBACK` ne laisse plus de verrou fantôme en shmem. `PREPARE TRANSACTION` est refusé (`0A000`) s'il reste des écritures shmem en attente ; une demande de rechargement y est simplement abandonnée. Hash plein : WARNING au COMMIT (plus d'ERROR). Le worker bénéficie du même mécanisme (`_shmem('unlock')` de `run_maintenance()` appliqué au `CommitTransactionCommand`). La remise à zéro des verrous shmem absents de `role_state` lors du rechargement (auto-réparation) n'est **pas** faite : elle entrerait en course avec un `lock_role` validé après la prise de l'instantané du worker.
- (revue) Hook d'authentification, verrou expiré : voir §6.3 (compteurs remis à zéro une seule fois, `locked_until` conservé tant que `lock_pending_audit`).
- (revue) `_require_target_allowed()` : définition étendue du rôle privilégié (§4) ; `create_rotation_pair()` l'applique aussi à `group_role` (un admin non superutilisateur obtenait sinon un rôle LOGIN membre de `postgres` ou de `pg_execute_server_program`). Décision : `assign_profile`/`alter_profile` restent ouvertes (option A, §4) ; `pg_pass_policy.exempt_roles` protège les superutilisateurs.
- (revue) `switch_rotation_pair()` inscrit la borne de l'ancien rôle dans `role_state` (`must_change`, `expires_at = grace_until = valid_until_synced = now() + grace_period`, `last_warned_at = now()`), comme `expire_password()`, et plus seulement par dérivation de `rotation_pair.previous_valid_until` : la disparition de la ligne de paire (groupe supprimé, DELETE) ne réactive plus l'ancien mot de passe à la synchronisation suivante. `run_maintenance()` étape a reporte `previous_valid_until` dans `role_state` avant de purger une paire (paires basculées avant cette correction). `v_role_status` affiche `grace` (et non `expired`) pour un rôle `must_change` dont `grace_until` est encore futur.
- (revue) `run_maintenance()` étape d avec `manage_valid_until = off` : mode `unblock` limité aux rôles dont `rolvaliduntil = valid_until_synced` et `must_change = false` (§5).
- (revue) `pg_pass_policy.database` inexistante : comportement standard conservé (FATAL + relance toutes les 10 s), documenté (§6.4, README).
- (finition) `DROP EXTENSION pg_pass_policy` supprime tous les objets de l'extension mais **laisse** le schéma `pass_policy` (vide) : il est déclaré par la clé `schema` du fichier `.control`, créé par `CREATE EXTENSION` sans appartenir à l'extension (comportement standard de PostgreSQL). Les rôles `pass_policy_admin` et `pass_policy_viewer` (objets globaux) survivent aussi. Désinstallation complète : `DROP EXTENSION pg_pass_policy; DROP SCHEMA pass_policy; DROP ROLE pass_policy_admin, pass_policy_viewer;`. `CREATE EXTENSION` réutilise les rôles s'ils existent (test `99_teardown`).
