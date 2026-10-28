# pg_pass_policy — spécification technique (contrat entre les composants)

Ce document est le contrat partagé par tous les développeurs/agents. Toute
modification d'une interface listée ici (table, fonction SQL, GUC, prototype C,
structure partagée) doit être reportée ici **avant** d'être codée.

Le projet est réparti en trois dépôts : l'extension (ce dépôt,
[`pg_pass_policy`](https://github.com/gliatti/pg_pass_policy)), la CLI
[`pg_pass_policy-cli`](https://github.com/gliatti/pg_pass_policy-cli)
et le back-office web
[`pg_pass_policy-web`](https://github.com/gliatti/pg_pass_policy-web).
Ce document reste leur spécification commune : les §9 et §10 décrivent les
deux clients, dont le code se trouve dans leurs dépôts.

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
docs/                         documentation
```

La CLI et le web ont chacun leur dépôt
([`pg_pass_policy-cli`](https://github.com/gliatti/pg_pass_policy-cli),
[`pg_pass_policy-web`](https://github.com/gliatti/pg_pass_policy-web)).

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
| min_length | int | 12 | ≥ `_min_generated_length()` = 8 (`PPP_GEN_MIN_LENGTH`) ; ≤ `max_length` (`profile_length_range`), donc ≤ 512 |
| max_length | int | 128 | ≤ `_max_generated_length()` = 512 (`PPP_GEN_MAX_LENGTH`, limite de `generate_password`) ; ≥ `min_length` et ≥ `_generator_minimum(min_lower, min_upper, min_digit, min_special, min_classes)`, longueur minimale que le générateur peut construire (`profile_classes_fit`) |
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
| `check_password(role text, password text)` | text | **C** — NULL si conforme, sinon le motif de refus (texte en anglais, préfixe stable `PPP-xxx`). Sans effet de bord. Même évaluation que le hook pour le même appelant, dans les deux sens (NULL ⇔ `ALTER ROLE … PASSWORD` accepté, code ⇔ même refus ; `ppp_evaluate_password()` : pré-haché, `min_age` ignoré pour un superutilisateur appelant comme par le hook), sauf `superuser_bypass`, ignoré (seule différence) ; hors de `pg_pass_policy.database` : ERROR `PPP-003` (SQLSTATE `55000`), quel que soit `enforce_database` |
| `generate_password(length int DEFAULT 24, profile text DEFAULT NULL)` | text | **C** — `pg_strong_random`, garanti conforme au profil (classes), alphabet sans caractères ambigus (`0O1lI|`) ; hors de `pg_pass_policy.database` : ERROR `PPP-003` avec `enforce_database = on`, sinon WARNING et mot de passe produit |
| `_generate_password_for(role name, length int, profile text)` | text | **C**, interne (aucun droit) — `generate_password()` dont les tirages ne contiennent ni le nom du rôle ni son inverse (`PPP-017`, si `reject_username`) ; utilisée par `_rotate_role()` |
| `rotate_password(role name, length int DEFAULT NULL)` | text | longueur NULL = 24 relevée au `min_length` du profil et à la longueur qu'exigent ses minima de classes (`_generator_minimum()` : `Max(min_lower, 1) + Max(min_upper, 1) + Max(min_digit, 1) + min_special`, plus un spécial si `min_classes` l'exige), bornée par `max_length`, longueur explicite hors bornes → `22023` ; génère, `ALTER ROLE … PASSWORD`, `VALID UNTIL` (`force` ; `release` si `manage_valid_until = off` ou rôle exempté : borne écrite par l'extension levée, même future, valeur posée à la main conservée), audit `password_rotated`, NOTIFY ; **retourne le mot de passe une seule fois** ; `SECURITY DEFINER` |
| `expire_password(role name)` | void | `must_change = true`, `VALID UNTIL now()`, audit ; rafraîchit `role_state.role_name` (nom courant) ; refusée pour un rôle de `exempt_roles` (`_require_not_exempt()` : `22023`, « role "…" is exempt from the policy », HINT « Remove it from pg_pass_policy.exempt_roles first. ») |
| `lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)` | timestamptz | refusée pour un rôle de `exempt_roles` (`_require_not_exempt()`, même refus qu'`expire_password()`) ; NULL = manuel ; met à jour `role_state` (dont `role_name` = nom courant) + `shmem_lock_role` ; renvoie le `locked_until` posé (`infinity` pour un verrou manuel) |
| `unlock_role(role name)` | void | `_ensure_state()` (ligne `role_state` créée si absente, `role_name` = nom courant) puis `role_state` + `shmem_unlock_role` + `shmem_reset_failures` ; audit `role_unlocked` seulement si le rôle était verrouillé (`role_state.locked_until` non NULL ou verrou actif en shmem d'après `_shmem_is_locked()`), sinon NOTICE sans audit |
| `record_password_change(role text, verifier text)` | void | appelée **par le hook C** via SPI après acceptation ; insère l'historique, tronque à `history_count`, met à jour `role_state`, audit `password_changed` |
| `rebind_restored_roles()` | TABLE(action text, role_name text, details jsonb) | superutilisateur seulement : après une restauration dans un autre cluster, rattache par nom les lignes de `role_state`, `role_profile` et `password_history` dont le couple (`role_oid`, `role_name`) ne correspond à aucun rôle (nom inexistant → purge) ; à appeler avant le premier `run_maintenance()` (README) |
| `run_maintenance()` | TABLE(action text, role_name text, details jsonb) | ce que fait le worker (appelable par pg_cron) : sync VALID UNTIL, alertes, expirations, déverrouillages auto, purge rôles disparus, réconciliation `pg_authid.rolpassword` vs historique, `shmem_reload()` ; une passe à la fois (`pg_advisory_xact_lock`) |
| `create_rotation_pair(pair text, role_a name, role_b name, group_role name)` | void | crée les rôles manquants (`LOGIN`, membres du groupe) |
| `switch_rotation_pair(pair text, length int DEFAULT NULL)` | TABLE(active_role text, password text, previous_role text, previous_valid_until timestamptz) | longueur comme `rotate_password()` |
| `purge_audit(older_than interval DEFAULT '365 days')` | bigint | |
| `load_dictionary(words text[])` | int | |
| `audit(event_type text, role_name text, details jsonb DEFAULT '{}')` | void | insère + `pg_notify(current_setting('pg_pass_policy.notify_channel'), json)` ; utilisée par toutes les autres ; `EXECUTE` à `pass_policy_admin` seulement |
| `failed_attempts()` | TABLE(role_name text, failed_count int, first_failure_at timestamptz, last_failure_at timestamptz, locked_until timestamptz) | **C** — lit la shmem ; les entrées de noms inexistants (aucun rôle de ce nom dans `pg_authid` au moment de l'appel : recherche syscache sur la copie, hors LWLock, faite seulement pour un appelant non superutilisateur, et non le drapeau `role_missing` de l'entrée, simple cache des classes d'éviction que le worker ne fait passer qu'à vrai, pour les entrées sans rien en attente : voulu, la vue doit être exacte au moment de la lecture, §12) ne sont nommées que pour un superutilisateur : pour les autres (viewer, admin), une seule ligne agrégée, `role_name` NULL (somme des compteurs, premier et dernier échec, verrou le plus tardif) |
| `_shmem_is_locked(role text)` | bool | **C**, interne, superutilisateur — vrai si la shmem porte un verrou actif du rôle (`HASH_FIND`) ; utilisée par `unlock_role()` |
| `shmem_reload()` | void | **C** — superutilisateur seulement (comme les autres `shmem_*`) ; demande, à la validation de la transaction appelante, au worker de recharger les paramètres de verrouillage dans la shmem (un ROLLBACK annule la demande) |
| `shmem_lock_role(role text, until timestamptz)` | void | **C** — `until` NULL = manuel (DT_NOEND) ; écriture shmem différée au COMMIT (annulée par ROLLBACK / ROLLBACK TO SAVEPOINT) ; nom sans rôle : ERROR `42704` ; l'OID du rôle est capturé à l'appel et appliqué au PRE_COMMIT même si le rôle est renommé ou supprimé ensuite dans la transaction (vérification 14 : plus d'ERROR au COMMIT) |
| `shmem_unlock_role(role text, expired_only boolean DEFAULT false)` | bool | **C** — différée au COMMIT ; ne lève pas un verrou automatique posé après la demande ; `expired_only` : ne lève qu'un verrou expiré (étape f de `run_maintenance()`) et renvoie false, sans rien différer, si la shmem porte un verrou actif au moment de l'appel ; true sinon |
| `shmem_reset_failures(role text)` | void | **C** — différée au COMMIT |
| `worker_status()` | TABLE(pid int, last_run timestamptz, last_reload timestamptz, tracked_roles int, locks_loaded bool) | **C** — `locks_loaded` : faux tant que la fenêtre de démarrage refuse les connexions (§6.3, « Démarrage ») |

Règles communes à l'API :

- rien n'est accordé à `PUBLIC` (ni `USAGE` sur le schéma, ni `EXECUTE`),
  sauf `EXECUTE` sur les trois bornes pures du générateur appelées par les
  `CHECK` de `profile` (`_min_generated_length()`, `_max_generated_length()`,
  `_generator_minimum()`) : un `CHECK` s'exécute avec les droits de celui qui
  écrit la ligne (`INSERT` / `UPDATE` direct, `pg_restore` par un
  non-superutilisateur), qui doit recevoir `23514` et non `42501`. Les
  requêtes SPI du hook C tournent en `BOOTSTRAP_SUPERUSERID`
  (`ppp_spi_begin()`), quel que soit l'utilisateur qui change son mot de
  passe. `effective_profile()` est accordée à `pass_policy_viewer` et
  `pass_policy_admin`, `audit()` à `pass_policy_admin`,
  `record_password_change()` à personne. En défense en profondeur,
  `record_password_change()` refuse tout appel hors du hook
  (`pass_policy._in_password_hook()` = false), et `audit()` tout appel d'un
  `session_user` qui n'est ni superutilisateur ni membre de
  `pass_policy_admin` (le hook ne l'appelle plus) : SQLSTATE `42501`
  (`insufficient_privilege`) ;
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
  grace_until, days_left, locked_until, failed_count, status, role_oid,
  is_exempt, expiry_state, valid_until)` avec
  `status` ∈ `ok | warning | grace | expired | locked | exempt |
  never_expires | unknown`, par priorité `locked` > `exempt` >
  `expiry_state` ; `exempt` = rôle de `pg_pass_policy.exempt_roles`
  (`_is_exempt()`) ; `unknown`
  = date de changement inconnue (rôle antérieur à l'extension) ;
  `role_oid` sert de clé de jointure avec `role_state`,
  dont `role_name` peut garder l'ancien nom après `ALTER ROLE … RENAME`.
  Colonnes ajoutées après `role_oid` (ordre des colonnes existantes
  conservé) : `is_exempt` (bool, `_is_exempt()`), `expiry_state` (`ok |
  warning | grace | expired | never_expires | unknown`, calculé
  indépendamment du verrou et de l'exemption : la priorité de `status`
  masquait qu'un rôle verrouillé ou exempté est aussi expiré) et
  `valid_until` (`pg_roles.rolvaliduntil`, ce que le serveur applique) ;
- `v_expiring` : `expiry_state` in (warning, grace, expired) et `NOT
  is_exempt` : un rôle verrouillé dont le mot de passe expire y figure, les
  rôles exemptés en sont exclus ;
- `v_locked(role_name, locked_until, locked_by, lock_reason, failed_count)` :
  `role_state` joint par OID ;
- `v_recent_audit` : 1000 derniers événements.

Message JSON de `NOTIFY` : `{"event":"…","role":"…","at":"…","details":{…}}`.

## 5. GUC (tous préfixés `pass_policy.`)

| nom | type | défaut | contexte | rôle |
|---|---|---|---|---|
| enabled | bool | on | SIGHUP | désactive hooks ; le worker est suspendu et ne modifie rien : ni `run_maintenance()`, ni audit en attente, ni `role_state`, ni nettoyage ou rechargement de la shmem (les échecs et verrous en attente y restent jusqu'au retour à `on`, voir §6.4) |
| database | string | postgres | postmaster | **seule** base où la politique s'applique : celle où est installée l'extension et où se connecte le worker ; une extension créée dans une autre base n'y est pas utilisée par le hook (§6.2, étape 2) |
| worker_interval | int (s) | 60 | SIGHUP | 0 = worker désactivé (appel manuel `run_maintenance`) |
| max_tracked_roles | int | 1024 | postmaster | taille du hash shmem |
| manage_valid_until | bool | on | SIGHUP | le worker écrit `rolvaliduntil` ; à `off`, `run_maintenance()` relève tout de même (mode `unblock`) un `VALID UNTIL` passé qu'elle a elle-même posé (`expire_password`, ancienne synchronisation) une fois le mot de passe changé ; `rotate_password()` et `switch_rotation_pair()` (`_rotate_role()`, mode `release`) relèvent une borne posée par l'extension même future, comme pour un rôle exempté |
| log_events | bool | on | SIGHUP | `ereport(LOG)` sur chaque événement (préfixe `pg_pass_policy:`) |
| notify_channel | string | pg_pass_policy | SIGHUP | |
| rescue_roles | string | '' | SIGHUP | superutilisateurs admis par `peer` pendant la fenêtre de démarrage (voie de secours, §6.3 « Démarrage ») ; mêmes règles de découpage que `exempt_roles` (même check hook, `ppp_role_is_rescue()`) ; vide : aucun accès de secours |
| exempt_roles | string | '' | SIGHUP | liste séparée par virgules exemptée de la politique et du verrouillage ; règles de `SplitIdentifierString()` (noms non quotés en minuscules ASCII, `"quotés"` tels quels, `""` = un guillemet, espaces ignorés), une seule implémentation en C (`ppp_role_is_exempt()`, liste découpée une fois par l'assign hook), appelée aussi par la fonction SQL `_is_exempt()` (symbole `ppp_is_exempt`) |
| superuser_bypass | bool | off | SIGHUP | si on : les superutilisateurs ne sont pas soumis à la complexité (hook seulement : `check_password()` l'ignore) |
| require_scram | bool | on | SIGHUP | refuse MD5 (`password_encryption = md5`) |
| enforce_database | bool | on | SIGHUP | hors de `pg_pass_policy.database`, `ALTER ROLE … PASSWORD` est refusé (`PPP-003`), que l'extension soit installée ou non dans la base courante (sinon seulement ignoré avec WARNING) |

PG ≥ 15 : `MarkGUCPrefixReserved("pg_pass_policy")`, sinon
`EmitWarningsOnPlaceholders`.

## 6. Contrat C (voir `src/pg_pass_policy.h`)

### 6.1 Propriétaires

| fichier | propriétaire | contenu |
|---|---|---|
| `pg_pass_policy.c` | agent « core » | `_PG_init`, GUC, `shmem_request_hook`/`RequestAddinShmemSpace`, `shmem_startup_hook` → `ppp_lockout_shmem_init()`, enregistrement du worker, `ppp_role_is_exempt`, `ppp_is_exempt`, `ppp_worker_status` |
| `policy.c` | agent « core » | hook mot de passe, `ppp_check_password`, `ppp_generate_password`, `ppp_generate_password_for` |
| `lockout.c` | agent « lockout/worker » | hook auth, hash shmem, `ppp_failed_attempts`, `ppp_shmem_*`, `ppp_shmem_is_locked` |
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
2. base courante puis état de l'extension, sans session SPI et avant toute élévation. **Hors de `pg_pass_policy.database`** (`current_database() <> ppp_database`), la politique ne s'applique jamais, **même si l'extension est installée dans la base courante** : ses tables n'y sont pas maintenues par le worker (ni `run_maintenance()`, ni audit, ni rechargement des verrous), y écrire un historique ou un état serait trompeur. Le hook s'exécute en effet dans la base courante de la session, pas dans `pg_pass_policy.database`. Avec `pg_pass_policy.enforce_database = on` (défaut) et `ppp_enabled`, `ALTER ROLE … PASSWORD` (et `CREATE ROLE … PASSWORD`) est refusé par l'ERROR `PPP-003` (« password changes must be made while connected to database X ») ; avec `off`, le changement est accepté sans politique, avec un WARNING « password policy not applied outside database X » une fois par session. **Dans `pg_pass_policy.database`** : état de l'extension (`ppp_require_extension()` → `ppp_extension_state()`) ; absente → **ne rien bloquer**, WARNING « extension is not installed in database X » une fois par session ; présente mais non fiable (schéma `pass_policy` absent, ou dont le propriétaire n'est pas superutilisateur) → ERROR `PPP-004` (« pg_pass_policy schema is not trusted », SQLSTATE `55000`, DETAIL sur le propriétaire), jamais d'acceptation sans politique ; installée et fiable → ouvrir la session SPI élevée et charger le profil effectif : `SELECT * FROM pass_policy.effective_profile($1)` ;
3. si `password_type != PASSWORD_TYPE_PLAINTEXT` : `reject_prehashed` → ERROR `PPP-001` ; vérificateur MD5 et `pg_pass_policy.require_scram` → ERROR `PPP-002` ; sinon enregistrer sans vérification de complexité (seul `min_age` est contrôlé). Pour un mot de passe en clair, `PPP-002` est aussi levé si `require_scram` et `password_encryption = md5` ;
4. vérifications de complexité (ordre et codes) : `PPP-010` longueur min, `PPP-011` longueur max, `PPP-012` classes (min_classes), `PPP-013` min_lower, `PPP-014` min_upper, `PPP-015` min_digit, `PPP-016` min_special, `PPP-017` contient le nom du rôle, `PPP-018` dictionnaire, `PPP-019` répétitions, `PPP-020` caractères non imprimables / espace en début-fin. Codes hors complexité : `PPP-001` pré-haché refusé, `PPP-002` MD5 refusé par `require_scram`, `PPP-003` changement hors de `pg_pass_policy.database` ;
5. `min_age` : `PPP-030` si `now() - password_changed_at < min_age` (sauf superutilisateur appelant, ignoré si `must_change`) ; pour un rôle existant, les étapes 5 et 6 ne sont faites que si l'appelant peut changer son mot de passe (superutilisateur, le rôle lui-même, ou `PPP_MAY_SET_PASSWORD_OF()` de `compat.h` : `is_admin_of_role()` sur PG ≥ 16, `CREATEROLE` et cible non superutilisateur sur PG ≤ 15), droits lus avant l'élévation ; sinon elles sont sautées en silence (pas d'oracle `PPP-030`/`PPP-031`), la complexité reste contrôlée. Défense en profondeur : `CreateRole()` et `AlterRole()` vérifient l'existence et les droits avant d'appeler le hook (sources 13.2, 16.4, 17beta1) ; `role_state` cherché par OID uniquement (rôle existant) ; la date retenue est la plus récente entre `role_state.password_changed_at` et la dernière ligne `password_history` sans OID (`role_oid IS NULL`) du même nom, écrite par `CREATE ROLE … PASSWORD` avant que `run_maintenance()` crée `role_state` ;
6. historique : mot de passe actuel (`pg_authid`) puis chaque vérificateur des `history_count` derniers (l'actuel compris, et plus récents que `history_days`), `scram_verify_plain_password(username, password, verifier)` → `PPP-031` si égal ; vérificateurs MD5 : comparés via `pg_md5_encrypt`. Pour un rôle existant : lignes de son OID **et** lignes `role_oid IS NULL` de son nom (`CREATE ROLE … PASSWORD` pas encore rattaché par `run_maintenance()`), jamais celles d'un autre OID ; pour un rôle pas encore créé (`CREATE ROLE`), par nom parmi les seules lignes `role_oid IS NULL` ;
7. calcul du nouveau vérificateur : `encrypt_password(PASSWORD_TYPE_SCRAM_SHA_256, username, shadow_pass)` (PG 14-18 : `libpq/crypt.h`) ; si `password_type == PLAINTEXT` ; sinon `shadow_pass` tel quel ;
8. SPI `SELECT pass_policy.record_password_change($1, $2)` ;
9. chaîner au hook précédent.

`check_password()` partage avec le hook les étapes 3 à 6
(`ppp_evaluate_password()`, type du mot de passe lu par
`get_password_type()`) et le prédicat des étapes 5 et 6
(`ppp_may_check_history()`) : sa réponse est celle que donnerait
`ALTER ROLE … PASSWORD` du même appelant, dans les deux sens (NULL : le
hook accepte ; un code : il refuse avec ce code), `min_age` compris (même
`caller_is_super` : ignoré pour un superutilisateur appelant, contrôlé pour
les autres, vérificateur pré-haché compris ; test `95_parity`). Seule
différence : `superuser_bypass` n'est appliqué que
par le hook (paramètre `bypass_complexity` de `ppp_evaluate_password()`) ;
`check_password()` répond pour le profil du rôle, même appelée par un
superutilisateur, pour qu'un client qui vérifie un mot de passe pour autrui
ne le croie pas conforme. Hors de `pg_pass_policy.database`, elle
lève `PPP-003` (SQLSTATE `55000`) quel que soit `enforce_database` : la
politique ne s'y applique pas, une réponse « conforme » n'aurait pas de sens.

Refus : `ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD), errmsg("PPP-0xx: …"), errdetail(…), errhint(…)))`. Le mot de passe n'apparaît **jamais** dans un message, un log ou l'audit. Un refus est journalisé par un `ereport(LOG)` direct en C (`pg_pass_policy: password_rejected role=<rôle> {"code": "PPP-0xx"}`, format de la ligne LOG de `_audit()`, sans STATEMENT ni CONTEXT, si `pg_pass_policy.log_events` est actif) : aucune ligne `audit_log` ni NOTIFY, que l'ERROR qui suit annulerait de toute façon.

Les caractères sont comptés en points de code UTF-8 (`pg_mblen`) ; les classes : minuscule / majuscule (`pg_wchar` + `iswlower/iswupper` ou ASCII suffisent + tout caractère non-ASCII compte comme « special »), chiffre ASCII, special = tout le reste imprimable.

### 6.3 Hook d'authentification et shmem (`lockout.c`)

Le hook s'exécute pendant `InitPostgres()`, **après** `InitCatalogCache()`,
`StartTransactionCommand()` et `GetTransactionSnapshot()` :
`PerformAuthentication()` est appelée une fois la transaction de démarrage
ouverte (vérifié dans les sources 13.2, 16.4 et 17beta1), et
`get_role_password()` y fait elle-même `SearchSysCache1(AUTHNAME)`. Le hook
peut donc consulter le cache système ; il ne fait **qu'une** recherche
(`SearchSysCache1(AUTHNAME)`, `ppp_role_lookup()` : existence du rôle, son
OID, `rolvaliduntil` et, pendant la fenêtre de démarrage, `rolsuper` ; à
chaque connexion, avant de prendre le LWLock, sautée si
`!IsTransactionState()`), **aucun SPI**. Tout le reste vient de la shmem,
remplie par le worker.

```
static void ppp_client_auth_hook(Port *port, int status);
```

1. si `!ppp_enabled` ou rôle exempt → chaîner au hook précédent et sortir ;
2. sinon le hook précédent est appelé après l'étape 8, **avant** le FATAL de l'étape 5 (un module chargé avant nous, `auth_delay` par exemple, voit toujours la tentative et son statut réel) ;
3. le rôle existe-t-il, quel est son OID, et son `rolvaliduntil` est-il passé (`SearchSysCache1(AUTHNAME)`, `ppp_role_lookup()`) ? La recherche n'est faite que si sa réponse sert (vérification 14) : échec à compter, fenêtre de démarrage, ou entrée trouvée d'abord sous verrou partagé (`HASH_FIND`) qui porte un verrou actif ou quelque chose en attente pour un OID connu (`ppp_lookup_needed()`) ; si l'entrée, retrouvée sous le verrou exclusif, en a besoin alors qu'elle n'en avait pas besoin sous le verrou partagé, le verrou exclusif est relâché pour la recherche puis repris ; Un rôle expiré refusé par une méthode à mot de passe stocké (`password`, `md5`, `scram-sha-256` : `get_role_password()` refuse alors même le bon mot de passe) n'est pas compté ; le refus d'un rôle verrouillé (étape 5) reste appliqué ;
4. `LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE)` ; chercher `port->user_name` dans `ppp_role_hash` ; si absent **et** `status == STATUS_ERROR` → créer avec les paramètres par défaut (`ppp_shared->default_*`) en mode « comptage » (`ppp_enter_role(…, PPP_ENTER_COUNT, …)`, voir « Hash plein » ci-dessous) ; faute de place → `ereport(LOG)` et continuer sans compter (un verrou existant reste appliqué : il a toujours une entrée) ; `role_missing` reçoit le résultat de l'étape 3 à la création **et à chaque échec** (un rôle créé après coup perd le drapeau), et est effacé par un succès ; le worker le rafraîchit aussi à chaque synchronisation (`ppp_sync_cleanup()` : noms copiés sous verrou partagé, recherche syscache hors LWLock, écriture sous verrou exclusif dans la même incarnation de l'entrée, `generation`) ; il ne sert qu'au classement d'éviction et à la purge : `failed_attempts()` vérifie l'existence du nom à chaque appel d'un non-superutilisateur (§4) ;
5. si `locked_until > now` (ou `DT_NOEND`) **et que le verrou n'est pas certainement celui d'un autre rôle** → `ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("role \"%s\" is locked by pg_pass_policy"), errdetail("locked until %s")))` — **même si status == STATUS_OK**. Principe : dans le doute, le verrou s'applique (fail-closed, vérification 14). Le verrou est certainement celui d'un autre rôle (`ppp_lock_is_foreign()`) seulement si la recherche de l'étape 3 a été faite et que `lock_role_oid` est valide et différent de l'OID trouvé, ou que le verrou est un pseudo-verrou certain (`lock_on_missing` : posé par le hook sur un nom qui n'avait pas de rôle) et qu'un rôle porte maintenant le nom ; tout autre verrou à `lock_role_oid` invalide s'applique, de même qu'un verrou quand la recherche a été sautée ou a échoué. Le verrou d'un autre rôle (supprimé, ou renommé, dont le nom est repris) : si l'entrée n'a rien en attente (`ppp_entry_settled()`), elle repart de zéro pour ce rôle (`ppp_restart_entry()` : `ppp_init_entry()`, donc verrou, compteurs, audit et paramètres du profil remis aux valeurs par défaut, nouvelle `generation`, et `reload_requested` levé, le worker étant réveillé après le relâchement du verrou : le rechargement fixe le profil du rôle qui porte le nom et réinjecte sous son nouveau nom le verrou persisté d'un rôle renommé) et la connexion suit les étapes 6 et 7 ; sinon (audit en attente de l'autre rôle, verrou non validé) la connexion est **refusée comme verrouillée**, quel que soit le statut, jusqu'à ce que le worker ait audité l'entrée (§12 : disponibilité sacrifiée à la sûreté ; la laisser passer sans compter permettait une force brute illimitée) ;
5 bis. propriétaire des compteurs (vérification 14) : `owner_oid` reçoit l'OID du rôle à chaque échec compté (recherche faite) ; pour un échec à compter ou un succès, si la recherche a été faite et que `owner_oid` est valide et différent de l'OID du rôle qui se connecte, l'entrée réglée repart de zéro (`ppp_restart_entry()`, comme à l'étape 5) avant de compter ; si quelque chose est en attente, la connexion est refusée comme verrouillée (« The role is temporarily locked; retry later. »), bon mot de passe compris (un succès admis alors que les échecs sont refusés serait un oracle), jusqu'au tour du worker. Le nouveau rôle n'hérite jamais des compteurs d'un rôle supprimé ;
6. si `status == STATUS_OK` → `failed_count = 0` ;
7. sinon (`STATUS_ERROR` d'une méthode qui vérifie un mot de passe ou un secret uniquement, voir « Méthodes comptées » ci-dessous et §11) : si la fenêtre est écoulée (`ppp_window_elapsed()`) → repartir à 0 ; incrémenter ; si `failed_count >= max_failures` et `max_failures > 0` → `locked_until = now + lock_duration` (ou `DT_NOEND`), `lock_pending_audit = true`, `audit_locked_until = locked_until`, `audit_lock_seq++` (numéro d'épisode ; `audit_acked_seq` rattrapé s'il n'y avait rien en attente), `lock_role_oid` = OID trouvé à l'étape 3, `lock_on_missing` = recherche faite et nom sans rôle, `ereport(LOG, "pg_pass_policy: role \"%s\" locked after %d failed attempts")` ;
8. si le rôle n'est pas refusé à l'étape 5, que `ppp_shared->locks_loaded` est faux (quelle que soit la méthode d'authentification, `trust`, `peer` ou `cert` compris) et que le rôle n'est pas un superutilisateur (`rolsuper`) alors que le worker est démontrablement absent, ni un superutilisateur de `pg_pass_policy.rescue_roles` authentifié avec succès par `peer` (`ppp_auth_is_peer()`, `ppp_role_is_rescue()`) (voir « Démarrage ») → refus « état non chargé », **quel que soit le statut**, et les étapes 6 et 7 sont sautées : l'entrée n'est pas modifiée (voir « Démarrage » ci-dessous) ; `LWLockRelease` ; le FATAL `57P03` est levé après le hook précédent, comme celui de l'étape 5.

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
Ce compromis laisse un oracle résiduel, atténué mais pas éliminé : il exige
de saturer le hash. Après avoir « verrouillé » un nom, un attaquant qui
remplit le hash d'autres noms inexistants (de l'ordre de `max_tracked_roles`
tentatives) fait évincer le pseudo-verrou d'un nom inexistant, alors que le
verrou d'un vrai rôle (`KEEP`) reste : une nouvelle tentative sur le nom
répond alors « authentication failed » au lieu de « locked ». Rendre les
pseudo-verrous non évincables rouvrirait le remplissage du hash par des noms
fantômes. Recommandation : `max_tracked_roles` largement supérieur au nombre
de rôles qui ont un profil ou un verrou, avec une marge.

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
| `INACTIVE` | compteur nul ou fenêtre écoulée, rien à journaliser, pas de verrou actif, pas de profil ; ou verrou expiré à l'audit périmé (voir ci-dessus) et compteur inactif ; un verrou expiré dont les échecs de l'épisode n'ont pas encore été remis à zéro (`ppp_expire_lock()`, paresseux) compte comme un compteur nul |
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
- coût : l'éviction n'a lieu qu'une fois le hash plein, sous le verrou
  exclusif. Le mode PRIORITY (rare : administrateur, worker) parcourt tout le
  hash. Le mode COUNT (chaque connexion en échec) est borné : au plus
  `PPP_EVICT_SCAN_LIMIT` (256) entrées par tentative, à partir du bucket où
  le parcours précédent s'est arrêté (`ppp_shared->evict_scan_bucket`), la
  victime étant la meilleure de cette fenêtre. Une fenêtre sans entrée
  évincable vaut « pas de place » pour cette tentative (échec non compté,
  sans LOG) ; quand les fenêtres infructueuses successives ont couvert tout
  le hash, mesuré en buckets (`evict_fruitless_from` / `evict_fruitless_wrapped` :
  un tour réel, sans double comptage des entrées revues à la reprise en
  milieu de chaîne), `ppp_shared->evict_failed_at` est posé et
  le hook ne reparcourt pas pendant 1 seconde (LOG « cannot track » au plus
  une fois par seconde).

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
  pendant la passe, que `role_state` ne connaît pas encore. Un verrou expiré
  n'y est pas effacé directement mais confié à `ppp_expire_lock()` : s'il
  attend encore son audit (`lock_pending_audit`, nouveau verrou automatique
  posé et expiré avant la passe), `locked_until` est conservé pour que le
  worker écrive sa ligne `role_locked` (sans `lifted_before_audit`) et le
  copie dans `role_state` avant de l'effacer ; les compteurs de l'épisode
  sont remis à zéro comme lorsque le hook ou le worker rencontrent le verrou
  expiré ;
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
décrémenté, `lock_pending_audit` effacé si `audit_lock_seq` n'a pas
changé, `audit_acked_seq` avancé jusqu'à l'épisode écrit). Un verrou
automatique qui en remplace un autre encore en attente d'audit (worker en
retard, standby avant promotion) écrase `audit_locked_until` : la ligne
`role_locked` écrite pour le dernier épisode porte alors
`details.lost_episodes` (nombre d'épisodes antérieurs restés sans ligne,
`audit_lock_seq - audit_acked_seq - 1`), et les pseudo-verrous agrégés des
noms inexistants les comptent aussi. Avant son COMMIT, l'étape vérifie sous
le LWLock que `lock_seq` des entrées dont elle a écrit `role_state` n'a pas
bougé depuis la copie (et que `lock_inflight` est nul) : sinon un
`lock_role()` / `unlock_role()` validé entre la copie et l'upsert (ou dont
l'upsert a attendu le verrou de ligne) serait écrasé, puis recopié en shmem
par le rechargement du même tour ; l'étape lève alors une ERROR (WARNING du
worker), rien n'est acquitté et le tour suivant repart de valeurs fraîches. Le `role_locked` d'un verrou automatique est écrit avec
`audit_locked_until` même si le verrou a été levé (`unlock_role()`) ou
remplacé (`lock_role()`) avant le passage du worker : ni `PPP_OP_UNLOCK`, ni
`PPP_OP_LOCK`, ni le rechargement n'effacent `lock_pending_audit` ; la copie
vers `role_state` n'est faite que si `locked_until = audit_locked_until`
(sinon `details.lifted_before_audit = true` si le verrou a été levé,
`locked_until` effacé, ou `details.replaced_by_manual = true` si l'entrée
porte un autre verrou : `lock_role()` ou verrou réinjecté depuis
`role_state`, d'après `locked_until` non nul lors de la copie, que ce
verrou soit encore actif ou déjà expiré ; un verrou expiré est conservé
dans l'entrée tant que l'audit est en attente, `ppp_expire_lock()`). Les entrées `role_missing` ne
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
`failure_window` (24 h si la fenêtre est ≤ 0) ; auparavant, le worker fait
des fantômes (`role_missing` passé de faux à vrai) les entrées sans verrou
actif de rôles supprimés ou renommés depuis la dernière tentative, et
retire du hash les entrées verrouillées dont le rôle n'existe plus
(vérification 11) ; seules sont concernées les entrées qui n'ont rien en
attente (ni `lock_pending_audit`, ni `pending_failures`, ni épisode non
acquitté `audit_acked_seq ≠ audit_lock_seq`, ni `lock_inflight` :
`ppp_entry_settled()`). Une entrée verrouillée ne devient **jamais**
fantôme (`ppp_entry_may_become_ghost()` refuse tout verrou actif) : des
noms inventés pourraient l'évincer. Le verrou est rattaché à l'OID de son
rôle (`lock_role_oid`, posé par le hook, par `shmem_lock_role()` au
PRE_COMMIT et par la réinjection depuis `role_state`) ; une fois le verrou
entièrement audité et acquitté, l'entrée est supprimée (`HASH_REMOVE`)
quand cet OID n'existe plus (`SearchSysCache1(AUTHOID)` : rôle supprimé),
avec un LOG « lock of dropped role "…" released », ou porte un autre nom
(renommé) **et** que `role_state` a, pour cet OID, une ligne dont
`locked_until` couvre le verrou, sur un primaire (`ppp_lock_persisted()`,
vérification 14), avec un LOG « lock of role "…" renamed to "…": reloaded
from role_state » et une demande de rechargement (`ppp_reload_pending`) :
le verrou persisté est réinjecté par OID sous le nouveau nom dans le même
tour (vérification 13). Sinon (verrou automatique non écrit avant le
renommage, verrou local d'un standby, ligne `role_state` d'un OID périmé)
l'entrée reste sous l'ancien nom : aucun verrou n'est perdu, et le hook ne
l'applique pas à un autre rôle qui porterait l'ancien nom (étape 5) ; le
rôle renommé, lui, n'est pas verrouillé sous son nouveau nom (§12). Un
rôle recréé sous l'ancien nom n'hérite jamais du verrou d'un autre OID :
tant que l'audit de l'ancien rôle est en attente, il est refusé comme
verrouillé, puis l'entrée est retirée par le worker ou remise à zéro par
le hook (étape 5). Recherche syscache hors LWLock limitée à ces deux sortes
d'entrées (drapeau faux sans verrou, ou verrou d'OID connu), copiées en une
seule passe sous verrou partagé (`ppp_alloc_hash_copy()`, une ligne par
entrée plus `PPP_HASH_COPY_MARGIN`), compaction en place des lignes dont le
rôle a disparu, écriture sous verrou exclusif pour la même incarnation
(`generation`), sans mise à jour du hook ni nouveau verrou depuis la copie
(`update_seq`, incrémenté à chaque succès ou échec compté, et partout où le
drapeau est remis à faux) et si l'entrée remplit encore les mêmes
conditions (même `lock_role_oid` pour un verrou). Une entrée qui a quelque
chose en attente garde son état : le worker écrit ses lignes `role_gone` /
`role_renamed` (`ppp_ack_pending()`), puis le nettoyage la retire. Le hook
ne remet pas non plus le drapeau à jour sur une entrée qu'il refuse
« locked », ni après un échec ni après un succès (vérification 12) ; le
pseudo-verrou certain d'un nom inventé ne s'applique pas au rôle créé
ensuite sous ce nom une fois l'entrée auditée ; avant, la connexion est
refusée (étape 5, vérifications 13 et 14). Le passage de vrai à faux reste au hook
d'authentification (succès, ou échec dont la recherche trouve le rôle) :
un fantôme dont le nom est repris par un nouveau rôle ne lui transmet pas
son pseudo-verrou par le worker. `failed_attempts()` garde sa propre
recherche (§12). Il réinjecte ensuite
les verrous de `role_state` des seuls rôles existants : par OID, ou, si
l'OID n'existe pas (restauration avant le remappage de l'étape a0 de
`run_maintenance()`), par nom, sous l'OID du rôle trouvé (vérification 12),
pourvu que `role_state` n'ait aucune ligne pour cet OID (vérification 13 :
la ligne réelle du rôle l'emporte sur une ligne périmée) ;
une ligne dont ni l'OID ni le nom n'existent (rôle supprimé, purgée par
`run_maintenance()`) est ignorée (vérification 11) et n'empêche pas la
fermeture de la fenêtre
**avant** de recharger les paramètres des
profils (`max_failures`, `failure_window`, `lock_duration`, bornés à
2^31 − 1 s ≈ 68 ans avant conversion en `int4`) pour chaque rôle de
`role_profile` + les valeurs du profil `default` dans `ppp_shared->default_*`.
Un verrou `lock_from_state` (réinjecté depuis `role_state`, ou posé par
`shmem_lock_role()` sur un primaire) qui ne figure plus dans `role_state` est
levé, sur le primaire comme sur un standby ; les verrous automatiques du hook
(`lock_from_state = false`) ne sont jamais levés par le rechargement. Un
appel direct à `shmem_lock_role()` sur un primaire, sans ligne `role_state`,
est donc levé au rechargement suivant (utiliser `lock_role()`) ;
`shmem_lock_role()` refuse un nom sans rôle (ERROR `42704`, vérification
12 : le verrou n'aurait pas d'OID et ne serait jamais libéré) et capture
l'OID à l'appel : le PRE_COMMIT l'applique même si le rôle a été renommé
ou supprimé depuis dans la transaction (vérification 14, qui remplace
l'ERROR au COMMIT de la vérification 13), le nettoyage du worker gère
ensuite le renommage ou la suppression ; sur un
standby, un tel verrou local n'est pas marqué `lock_from_state` et survit
aux rechargements.

**Démarrage (fenêtre fail-closed).** Au démarrage (`shmem_startup`, y
compris la réinitialisation qui suit un crash d'un processus), le hash est
vide : un rôle verrouillé dans `role_state` (verrou manuel `infinity` posé sur
un compte compromis compris) n'est pas connu du hook tant que le worker ne
l'a pas réinjecté, et une session ouverte pendant ce temps survit à la
réinjection. D'où deux mesures :

- le worker fait de ce rechargement la **première** action de son premier
  tour (§6.4, `ppp_sync_first`), avant `run_maintenance()` (passe complète,
  attente éventuelle du verrou consultatif tenu par pg_cron) et l'étape
  d'audit ;
- tant que `ppp_shared->locks_loaded` est faux, le hook refuse les rôles non
  exemptés, **quelle que soit la méthode d'authentification** (`trust`,
  `peer`, `cert`, `gss`, `sspi` compris : un rôle verrouillé dans
  `role_state` passerait sinon par une ligne de `pg_hba.conf` sans secret),
  superutilisateurs compris sauf worker absent ou accès local de secours
  (étape 8 et points suivants) :
  `ereport(FATAL, (errcode(ERRCODE_CANNOT_CONNECT_NOW), errmsg("pg_pass_policy: lock state not loaded yet, retry")))`
  (SQLSTATE `57P03`, celui de « the database system is starting up » : les
  clients et les pools le traitent comme un refus temporaire). Le refus vaut
  pour le bon comme pour le mauvais mot de passe : pas d'oracle. Un LOG
  « refusing connections until the background worker has loaded the lock
  state » est écrit au plus une fois par seconde pour toute l'instance
  (`ppp_shared->not_loaded_logged_at`, sous le LWLock). L'entrée du rôle
  refusé n'est pas modifiée pendant la fenêtre : ni échec compté (le client
  reçoit « retry » quel que soit le mot de passe : rien n'est appliqué), ni
  remise à zéro du compteur par un succès (sinon « 4 mauvais + candidat +
  mauvais » révélerait, par le « locked » qui suit la fenêtre, si le
  candidat était le bon mot de passe). Un verrou déjà présent en shmem (posé
  par le hook) garde la priorité : FATAL « locked » de l'étape 5 ;
- **worker absent** : `RegisterBackgroundWorker()` ne signale pas un refus
  (`max_worker_processes` épuisé), et `_PG_init` ne peut pas savoir s'il
  restera une place. Le worker est tenu pour absent quand aucun worker n'a
  publié son PID (`worker_pid = 0`) plus de `PPP_WORKER_MISSING_GRACE_SECS`
  (10 s) après l'initialisation de la shmem (`ppp_shared->shmem_init_at`) :
  jamais démarré, ou incapable de se connecter (`pg_pass_policy.database`
  inexistante). Dans ce cas seulement, les **superutilisateurs** ne reçoivent
  plus le `57P03` : ils obtiennent la vraie réponse, leurs échecs sont
  comptés et ils restent soumis au FATAL « locked » d'un verrou présent en
  shmem. Sans cela, avec `exempt_roles` vide (défaut), une installation dont
  le worker ne démarre jamais refuserait toutes les connexions par mot de
  passe, `postgres` compris. Pendant un démarrage normal (worker présent,
  rechargement en cours ou en échec), ils sont refusés comme les autres : un
  superutilisateur verrouillé à la main dans `role_state` reste dehors, et la
  réponse ne distingue pas un nom de superutilisateur d'un autre nom
  (l'oracle résiduel n'existe que worker absent, §12). Le hook écrit alors
  un `LOG` « pg_pass_policy: worker has not loaded the lock state yet
  (worker_pid = 0) » (HINT : vérifier `max_worker_processes` et
  `pg_pass_policy.database`), au plus une fois par minute pour toute
  l'instance (`ppp_shared->worker_missing_logged_at`) ;
- **accès local de secours** (vérification 7, restreint en vérification 8) :
  un **superutilisateur listé dans `pg_pass_policy.rescue_roles`**
  (`ppp_role_is_rescue()`, vide par défaut : aucun accès de secours)
  authentifié avec succès (`STATUS_OK`) par `peer` (`ppp_auth_is_peer()`)
  passe quel que soit l'état du worker. La fenêtre peut en effet rester
  fermée indéfiniment worker présent (extension non fiable, verrous trop
  nombreux pour `max_tracked_roles`, `role_state` illisible) : sans cette
  voie, seuls les rôles de `exempt_roles` pourraient encore administrer
  l'instance. Le hook ne peut pas savoir si ce superutilisateur porte un
  verrou dans `role_state` (pas de SPI dans `ClientAuthentication_hook`, et
  le worker ne l'a pas encore chargé) : l'accès est donc réservé aux rôles
  que l'administrateur a listés en connaissance de cause, et à `peer`, qui
  lie le rôle à un compte système du serveur. `trust` n'en bénéficie pas,
  même sur socket Unix (il ne vérifie rien : tout compte local autorisé sur
  le socket choisit son nom de rôle). Un verrou présent en shmem le refuse
  toujours (« locked », étape 5) ; un contrôle `peer` en échec garde le
  `57P03` (pas d'oracle « nom de superutilisateur ») ; un rôle listé non
  superutilisateur reçoit le `57P03`. Le hook écrit un LOG « superuser "…"
  admitted by peer authentication before the lock state is loaded », avec
  le nom du rôle, une fois par rôle et par minute (vérification 10) : un
  tableau fixe de `PPP_RESCUE_LOG_SLOTS` (16) cases en shmem
  (`ppp_shared->rescue_log`, nom, horodatage du dernier LOG, compteur des
  admissions non journalisées, sous le verrou du hook) ; le LOG suivant du
  rôle donne ce nombre (« N earlier admission(s) of this role … not
  logged », au pluriel près ; période dérivée de `PPP_RESCUE_LOG_SECS` dans
  les textes). Le worker, à chaque synchronisation
  (`ppp_flush_rescue_log()`, avant le nettoyage et de nouveau après le
  rechargement, vérification 12), journalise lui-même ce nombre une fois la
  période du rôle écoulée, et tous les compteurs en attente dès que la
  fenêtre est fermée (vérification 11) : aucune admission ne reste non
  journalisée quand la fenêtre se ferme. Une horloge qui recule compte comme
  une période écoulée. Une case est prise à la première admission (libre, ou case
  d'un autre rôle dont la minute est écoulée sans rien à signaler) ;
  tableau plein, l'admission est journalisée sans limite : un rôle n'est
  jamais masqué. Le refus `57P03` ne porte aucun HINT (vérification 10,
  §12) : l'information complète (`exempt_roles`, superutilisateurs de
  `rescue_roles` en `peer`, tout superutilisateur une fois le worker absent
  `PPP_WORKER_MISSING_GRACE_SECS` après l'initialisation de la shmem) est
  dans le HINT du LOG « refusing connections until the background worker
  has loaded the lock state » (au plus une ligne par seconde) ;
- **rien n'est dit au client** : hormis les FATAL de refus (« locked »,
  `57P03` dont le DETAIL se borne à « The server has just started; retry in
  a few seconds. », sans HINT), tous les messages du hook sont de niveau `LOG` (log
  serveur seulement), sans mention du worker, de `exempt_roles` ni de
  `rescue_roles`.
  PostgreSQL n'envoie déjà au client, pendant l'authentification
  (`ClientAuthInProgress`), que les messages de niveau ERROR et plus
  (`should_output_to_client()`, vérifié dans 16.4) ; le niveau `LOG` ne
  dépend pas de ce filtre. Les limiteurs « au plus une fois par N s » du
  hook et du worker passent par `ppp_log_due(&last, now, msec)`
  (`pg_pass_policy.h`).

`locks_loaded` passe à vrai à la fin de `ppp_sync_reload()` (en même temps que
`worker_last_reload`) **si tous les verrous de `role_state` ont été
réinjectés** : un verrou sans place (hash plein d'entrées `KEEP`) laisse la
fenêtre fermée, avec un LOG « %d persisted locks could not be loaded in
shared memory: connections stay refused », et le rechargement reste en
attente (`ppp_sync_reload()` renvoie faux), retenté au tour suivant. Un
profil sans place ne retient pas la fenêtre (le rôle est compté avec les
valeurs par défaut). Ce LOG est écrit au plus une fois par minute (le
rechargement, lui, est retenté toutes les 5 s). `locks_loaded` passe aussi à vrai dès que le worker
constate que l'extension n'est **pas installée** dans
`pg_pass_policy.database` (`PPP_EXT_ABSENT` : aucun verrou persistant à
réinjecter ; sans cela, aucun rôle non exempté ne pourrait se connecter
avant `CREATE EXTENSION`) ; la demande de rechargement et `ppp_sync_first`
sont alors effacées (rien à recharger : pas de transaction de
synchronisation supplémentaire à chaque tour ; après `CREATE EXTENSION`,
`run_maintenance()` demande le rechargement). Une extension présente mais
non fiable (`PPP_EXT_UNTRUSTED` : schéma `pass_policy` cédé à un
non-superutilisateur, par exemple) laisse la fenêtre fermée ; le worker
l'écrit en `WARNING` « extension in database "x" is not trusted, the worker
does nothing », DETAIL nommant le propriétaire du schéma
(`ppp_untrusted_detail()`, partagé avec PPP-004), au plus une fois par
minute. Il n'est remis à faux que par l'initialisation de la shmem ;
`worker_status().locks_loaded` l'expose.

Tant que la fenêtre est fermée (ou, avec `worker_interval = 0`, tant qu'un
rechargement est en attente), le worker se réveille au plus
`PPP_RETRY_SECS` (5 s) plus tard, quel que soit `worker_interval`, sur un
standby comme sur un primaire. Sur un primaire, tant que la synchronisation
de tête (`ppp_sync_first`) échoue, ces réveils ne refont que cette
synchronisation : le tour complet (maintenance, audit, seconde
synchronisation) garde le rythme de `worker_interval` (premier tour,
demande `shmem_reload()` ou SIGHUP compris).

Cas particuliers :

- `pg_pass_policy.enabled = off` : le hook ne fait rien (étape 1), donc ne
  bloque pas non plus ; au retour à `on`, le hook ne refuse (57P03) que si
  aucun rechargement n'a encore réussi depuis le démarrage, et le premier
  tour du worker recharge avant toute autre étape ;
- `pg_pass_policy.worker_interval = 0` : le worker fait quand même un premier
  tour au démarrage (synchronisation seule, avec rechargement) ; si ce
  rechargement échoue, il est retenté toutes les 5 s (`PPP_RETRY_SECS`), sans
  attendre de SIGHUP, jusqu'à ce qu'il réussisse ;
- hot standby : le tour de lecture seule recharge à chaque tour et pose
  `locks_loaded` dès le premier ;
- worker absent ou bloqué (base `pg_pass_policy.database` inexistante,
  `max_worker_processes` épuisé, `role_state` illisible, verrous trop
  nombreux pour `max_tracked_roles`) : la fenêtre reste fermée, c'est voulu
  (fail-closed) ; les rôles de `pg_pass_policy.exempt_roles` (typiquement
  `postgres`) et les superutilisateurs authentifiés en `peer` ou en `trust`
  sur socket Unix passent toujours : c'est le filet de sécurité de
  l'administrateur, avec les superutilisateurs par mot de passe quand le
  worker est absent (ci-dessus). Le LOG « worker_pid = 0 » (worker jamais démarré),
  le LOG limité à une ligne par seconde, `worker_status().locks_loaded` faux
  et `last_reload` NULL (ou `pid` NULL) signalent la situation.

### 6.4 Worker (`worker.c`)

- enregistré dans `_PG_init` via `RegisterBackgroundWorker` (`BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION`, `BgWorkerStart_ConsistentState` pour tourner aussi sur un hot standby, `bgw_restart_time = 10`) ;
- `ppp_worker_main` : `BackgroundWorkerInitializeConnection(ppp_database, NULL, 0)` puis `search_path = pg_catalog, pg_temp` (le worker est superutilisateur : toutes ses requêtes sont qualifiées, `pg_catalog.jsonb_build_object` compris), boucle `WaitLatch` avec `ppp_worker_interval` ; sur `reload_requested` ou SIGHUP → tour immédiat ;
- la base `pg_pass_policy.database` doit exister au démarrage : sinon `BackgroundWorkerInitializeConnection` lève le FATAL standard « database "x" does not exist » et le postmaster relance le worker toutes les 10 s (comportement standard des bgworkers, identique à pg_cron) ; le GUC étant `postmaster`, corriger puis redémarrer ;
- premier tour d'un primaire après le démarrage, après une promotion ou après le retour de `enabled` à `on` (`ppp_sync_first`) : synchronisation shmem (nettoyage + rechargement **forcé**) **avant** `run_maintenance()` et l'étape d'audit, pour que les verrous de `role_state` soient réinjectés sans attendre une passe de maintenance (§6.3, « Démarrage ») ; la demande de rechargement est consommée, `run_maintenance()` en fait une nouvelle, servie par la synchronisation de fin de tour. En cas d'échec (erreur, verrous de `role_state` qui ne tiennent pas tous dans le hash), le tour suivant recommence par là, au plus 5 s plus tard tant que la fenêtre de démarrage est fermée ; ces relances ne refont que la synchronisation, le tour complet restant au rythme de `worker_interval` (§6.3) ; une extension absente efface la demande (rien à recharger, §6.3) ;
- chaque tour : `StartTransactionCommand` → si l'extension n'est pas installée (`get_extension_oid("pg_pass_policy", true) == InvalidOid`) → attendre ; sinon `SPI_execute("SELECT * FROM pass_policy.run_maintenance()")`, puis synchronisation shmem (§6.3) ; `CommitTransactionCommand`. `run_maintenance()` prend `pg_advisory_xact_lock(hashtext('pg_pass_policy.run_maintenance'))` en tête : une passe du worker, de pg_cron ou manuelle attend la fin d'une passe concurrente au lieu d'agir sur les mêmes lignes (audits et NOTIFY en double) ;
- l'étape d'audit regroupe les noms inexistants (`role_missing`) en une ligne `auth_failed` par tour (§6.3) : un flot de noms inventés ne produit plus une ligne et un NOTIFY par nom ;
- sur un hot standby (`RecoveryInProgress()`), tour en **lecture seule** (`ppp_worker_cycle_standby`) : ni `run_maintenance()` ni l'étape d'audit en attente (elles écrivent) ; les échecs et verrous comptés localement par le hook **ne sont pas acquittés** : `pending_failures` et `lock_pending_audit` restent posés (les entrées de vrais rôles concernées ne sont alors pas évincables par le hook, c'est voulu, sauf celles dont le verrou a expiré : sur un standby leur audit est aussitôt « périmé » et elles redeviennent évincables, voir « Perte bornée » §6.3 ; un verrou local expiré n'est pas effacé par le worker mais ne bloque plus, voir « verrou expiré » §6.3) et le premier tour après promotion les écrit dans `audit_log` et `role_state`. Puis nettoyage + rechargement **forcé à chaque tour** (`shmem_reload()` du primaire ne peut pas atteindre le worker du standby) : SELECT uniquement, dans une transaction que PostgreSQL force en lecture seule pendant la récupération. Intervalle : `worker_interval`, 60 s s'il vaut 0 (le standby doit sonder, rien ne le réveille) ; tant que la fenêtre de démarrage est fermée (premier rechargement en échec), au plus 5 s. Un verrou réinjecté depuis `role_state` (`lock_from_state`) qui n'y figure plus est levé (unlock ou expiration sur le primaire) ; les verrous posés localement (hook, ou `shmem_lock_role()` sur le standby) ne sont pas levés par le rechargement : ils expirent selon `lock_duration`, ou un superutilisateur appelle `pass_policy.shmem_unlock_role()` sur le standby (fonctionne en lecture seule). Après promotion, le tour suivant est un tour normal avec audit des échecs et verrous en attente et rechargement complet ;
- `pg_pass_policy.enabled = off` (`ppp_worker_suspended()`) : le tour entier est sauté, sur le primaire comme sur un standby (ni `run_maintenance()`, ni écriture d'audit ou de `role_state`, ni nettoyage ni rechargement de la shmem ; `worker_status().last_run` et `last_reload` n'avancent plus). Les échecs et verrous en attente restent en shmem (entrées `PENDING_AUDIT` / `KEEP`, éviction selon §6.3) ; une demande `shmem_reload()` est mémorisée. Le premier tour après le retour à `on` fait tout, avec un rechargement forcé (profils ou `role_state` ont pu changer, restauration par exemple). Un LOG à chaque transition (« worker suspended » / « worker resumed ») ;
- sans `hot_standby`, aucune connexion n'est acceptée pendant la récupération : le worker démarre à la fin de celle-ci ;
- `pg_pass_policy.worker_interval = 0` → après un premier tour au démarrage (synchronisation shmem seule, avec rechargement : il ferme la fenêtre fail-closed de §6.3), le worker dort indéfiniment (réveil sur SIGHUP ou `shmem_reload()`) ; tant que ce rechargement n'a pas réussi (fenêtre fermée ou rechargement en attente), il est retenté toutes les 5 s (`PPP_RETRY_SECS`) ;
- `RegisterBackgroundWorker()` ne signale pas un refus faute de place (`max_worker_processes`) : le hook d'authentification le détecte (`worker_pid = 0`) et le signale par un LOG limité (§6.3, « Démarrage »).

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
- `test/shell/lockout.sh` (`fsync = on`) : vraies connexions `psql` avec `PGPASSWORD` erroné → vérifie le FATAL « locked », l'expiration du verrou, `unlock_role`, l'application effective des paramètres rechargés (`max_failures = 2`), le verrou expiré avant le passage du worker (audit conservé, reverrouillage), `lock_duration` de 100 ans et NULL, `lock_role`/`unlock_role` sous ROLLBACK et SAVEPOINT, la fenêtre fail-closed du redémarrage (verrou manuel jamais contourné, 57P03, rôle exempté accepté) ;
- `test/shell/expiry.sh` : profil `max_age = '1 second'`, attend le worker, vérifie `rolvaliduntil` et le refus de connexion ; un rôle expiré qui retape 6 fois le bon mot de passe n'est pas verrouillé ;
- `test/shell/scs_off.sh` : `standard_conforming_strings = off` dans `postgresql.conf` : `CREATE EXTENSION` réussit, dictionnaire avec antislashs ;
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

## 9. CLI ([`pg_pass_policy-cli`](https://github.com/gliatti/pg_pass_policy-cli), Rust, clap + sqlx + tokio, nom du binaire `pgpp`)

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

## 10. Web ([`pg_pass_policy-web`](https://github.com/gliatti/pg_pass_policy-web), FastAPI + HTMX + Jinja2, psycopg 3, venv)

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
  1. un flot de noms inexistants bloquait le comptage d'un vrai rôle jusqu'au tour suivant du worker (les entrées fantômes, compteur vivant et échecs non journalisés, n'étaient pas évincables avant d'avoir été marquées par le worker ; reproduit : 16 fantômes puis 5 échecs sur un vrai rôle → aucun compteur, connexion acceptée). Le hook vérifie désormais lui-même l'existence du rôle (`get_role_oid(nom, true)` : le cache système est disponible pendant `PerformAuthentication()`, comme pour `get_role_password()`), à la création de l'entrée et à chaque échec ; une entrée `role_missing` est toujours évincable, même pseudo-verrouillée. Les noms inexistants restent comptés et « verrouillés » (réponse uniforme). L'oracle d'énumération est atténué, pas éliminé : il exige de saturer le hash, voir (revue finale 4) H1 ;
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
- (code-review) C4 — `check_password()` ne contrôle `min_age` que si l'appelant peut consulter l'historique (superutilisateur ou le rôle lui-même) : sinon `PPP-030` renseignait sur la date du dernier changement d'un autre rôle. Test : `90_privileges` (`admin_check_other`). *Élargi* : même prédicat que le hook, voir (revue finale 4) H2.
- (code-review) C5 — dictionnaire : colonne générée `word_sha256` (index unique) et requête `SELECT 1 … WHERE word_sha256 = $1` avec le SHA-256 du mot de passe en minuscules calculé en C. Le digest passe par `DirectFunctionCall1(sha256_bytea, …)` (fonction SQL `sha256()`, même signature fmgr de PG 11 à 18) plutôt que par `common/cryptohash.h`, dont la signature n'a pu être vérifiée que sur 16.4 et 17beta1 (absent de 13.2). L'expression `sha256(convert_to(word, 'UTF8'))` proposée n'est pas utilisable : `convert_to()` est STABLE (interdit dans une colonne générée) ; `textsend()` convertit vers l'encodage du client. Retenu : `sha256(decode(replace(word, '\', '\\'), 'escape'))`, IMMUTABLE, octets bruts dans l'encodage du serveur, comme `ppp_lower()` côté C. Le mot de passe en clair ne transite toujours pas ; le digest est un paramètre lié d'une requête SPI, que ni `log_statement` ni `log_parameter_max_length` ne journalisent (ils ne visent que l'instruction de premier niveau), auto_explain étant neutralisé par `ppp_spi_begin()`. Le tampon d'entrée et le digest sont effacés. `load_dictionary()` et le trigger de normalisation sont inchangés (la colonne est calculée après les triggers BEFORE). Test : `20_complexity` (mot avec `\`, cohérence des digests).
- (code-review) C6 — une seule session SPI élevée par point d'entrée : le hook (ouverte après le test `enabled`/exempté, puis, depuis (code-review 2) R5, seulement si l'extension est installée et fiable ; fermée à la fin ; en cas d'erreur, identité restaurée et relance masquée, GUC et connexion SPI libérés par l'abandon de la (sous-)transaction), `check_password()` et `generate_password()`. `superuser()` et `GetUserId()` de l'appelant sont lus avant l'élévation et passés aux fonctions de contrôle (`caller_is_super`). L'audit `password_rejected` s'exécute dans une sous-transaction de cette même session (*remplacé* : simple `ereport(LOG)`, voir (revue finale 4)). Les chaînes du profil et les résultats sont alloués dans le contexte mémoire antérieur à `SPI_connect()` (`pppSpiState.outer_cxt`).
- (code-review) C7 — wrapper `ppp_schema_exists()` supprimé ; commentaire « Wipe memory… » replacé au-dessus de `ppp_secure_zero()`.
- (code-review) C8 — DETAIL de `PPP-031` : « The password must differ from the last %d passwords (current one included). » (§3.1 aligné).
- (code-review) C9 — alphabet complet de `generate_password()` en constante statique (`ppp_alpha_all`), plus de `psprintf` à chaque essai ; le tampon est aussi effacé si une ERROR survient pendant la génération.
- (code-review) C10 (*remplacé*, voir (clôture) point 2) — `exempt_roles` découpé une fois par un assign hook dans un contexte mémoire privé (`ppp_exempt_cxt`), `ppp_role_is_exempt()` ne fait plus que des `strcmp`. Le pointeur `extra` n'a pas été retenu : il doit être alloué par `malloc()` jusqu'à PG 15 et par `guc_malloc()` à partir de PG 16 (`guc_free()` fait un `pfree()`), test de version que seul `compat.h` peut faire (§6.5) et que ce lot ne pouvait pas modifier. Allocations en `MCXT_ALLOC_NO_OOM` ; en cas d'échec, `ppp_role_is_exempt()` repasse au découpage à chaque appel. Sémantique inchangée (S2).
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
- (revue finale 2) F3, suite — le test `standby.sh` échouait selon la phase du worker : la remise à zéro des échecs ayant mené à un verrou expiré (`ppp_expire_lock()`) n'a lieu qu'à la tentative suivante du même rôle ou au tour suivant du worker ; entre l'expiration et ce tour, `failed_count` valait encore `max_failures` et `ppp_entry_real_class()` classait l'entrée `LIVE_COUNTER` (non évincable par le hook). Le 17e rôle n'était alors pas compté (« cannot track »). La classe ne dépend plus de ce moment : un verrou expiré (hors verrou en cours de validation, `lock_inflight`) dont `first_failure_at` précède `locked_until` est `INACTIVE`. Concerne aussi le primaire (jusqu'à `worker_interval` après l'expiration). Test : `standby.sh` passe `worker_interval` à 3600 pendant le scénario, ce qui le rend déterministe (échoue à chaque fois sans la correction).
- (revue finale 2) F4 — `PPP_OP_UNLOCK` effaçait au COMMIT tout verrou, y compris un verrou automatique plus récent. Horodatage `lock_set_at` (pose, hook et PRE_COMMIT) et `queued_at` (demande) ; au COMMIT, un verrou actif n'est levé que s'il est `lock_from_state` ou si `lock_set_at <= queued_at`, sinon il est conservé (LOG). Cela ne suffisait pas pour l'étape f de `run_maintenance()` : le nouveau verrou peut être posé **avant** la passe (la shmem a déjà oublié le verrou expiré que `role_state` porte encore), donc avant `queued_at`. D'où `shmem_unlock_role(role, expired_only => true)` (`_shmem('unlock_expired')`), qui ne lève jamais un verrou actif. Test : `lockout.sh` (worker à 600 s, verrou automatique expiré dans `role_state`, 5 nouveaux échecs, `run_maintenance()` manuel : `role_unlocked` écrit, rôle toujours verrouillé, verrou recopié dans `role_state` au tour suivant ; échoue avec l'ancien `_shmem('unlock')`).
- (revue finale 2) F5 — les échecs en attente des noms inexistants produisaient une ligne `auth_failed` et un NOTIFY par nom inventé et par tour. Une seule ligne agrégée par tour, `role_name` NULL, `details` `{"unknown_roles", "attempts", "pseudo_locks", "last_failure_at", "source"}` ; les pseudo-verrous des noms inexistants y sont comptés au lieu d'une ligne `role_locked` chacun (choix fait ici : même problème de volume). Test : `lockout.sh` (3 noms × 2 échecs → une ligne `1:3/6`, aucune ligne au nom des fantômes).
- (revue finale 2) F6 — logique « verrou expiré » commune au hook et au worker : `ppp_expire_lock(entry, now, check_inflight)` (`pg_pass_policy.h`). Écart résorbé : le worker remet désormais aussi à zéro le compteur de l'épisode expiré quand l'audit est encore en attente, comme le hook le faisait déjà.
- (revue finale 2) F7 — `_require_target_allowed()` ne parcourt plus tout `pg_authid` avec `_is_privileged()` + `pg_has_role()` par rôle : `WITH RECURSIVE` sur `pg_auth_members` depuis la cible (toutes les attributions, sans tenir compte d'`INHERIT`/`SET`, comme `is_member_of_role()` / `roles_is_member_of(ROLERECURSE_MEMBERS)` de 16.4), plus l'appartenance implicite du propriétaire de la base à `pg_database_owner` que `roles_is_member_of()` ajoute ; `_is_privileged()` n'est appliqué qu'aux ancêtres. `pg_database_owner` ne peut être membre d'aucun rôle en 16.4 et 17beta1 (« cannot be a member of any role »), la branche implicite est gardée pour rester identique à `pg_has_role()` sur PG 14 et 15 (non vérifié dans leurs sources). Équivalence vérifiée sur une instance 16.4 (ancien et nouveau prédicat sur tous les rôles, dont grants `INHERIT FALSE` et `SET FALSE`, chaînes et propriétaire de base) ; `90_privileges` inchangé et vert.
- (revue finale 2) F8 — `ppp_begin_materialize(fcinfo, &tupdesc, &tupstore, expected_natts)` (`pg_pass_policy.c`, exportée) remplace le code SRF dupliqué de `failed_attempts()` et `worker_status()`.
- (revue finale 2) F9 — `check_password()` est `STRICT` : test `PG_ARGISNULL` retiré (code mort), de même dans `shmem_unlock_role()` et `shmem_reset_failures()`, `STRICT` aussi ; `shmem_lock_role()` (non `STRICT`, `until` NULL = manuel) et `generate_password()` gardent les leurs.
- (revue finale 3) G1 — la colonne générée `dictionary.word_sha256` écrivait l'antislash `'\'` / `'\\'` : avec `standard_conforming_strings = off` (paramètre du serveur, appliqué au script d'extension), le littéral changeait de sens et `CREATE EXTENSION` échouait. Écrit `chr(92)` (`IMMUTABLE`), même expression dans les deux modes. Test : `test/shell/scs_off.sh` (instance à `off`, mots avec un et deux antislashs : condensat = SHA-256 des octets bruts, `PPP-018` par `check_password()` et par `ALTER ROLE`).
- (revue finale 3) G2 — un rôle dont `rolvaliduntil` est passé est refusé par `get_role_password()` même avec le bon mot de passe : ces `STATUS_ERROR` étaient comptés et le titulaire qui retapait son mot de passe verrouillait son rôle. Le hook lit `rolvaliduntil` dans la même recherche syscache (`AUTHNAME`) que l'existence du rôle (`ppp_role_lookup()`) et ne compte pas l'échec d'un rôle expiré pour `password`, `md5` et `scram-sha-256` (`ppp_auth_method_checks_valid_until()`) ; `ldap`, `pam`, `radius` et `bsd` ignorent `rolvaliduntil` et restent comptés. Pas d'oracle : la connexion est refusée de toute façon (mêmes messages qu'avant), et le refus « locked » d'un rôle déjà verrouillé reste appliqué. Test : `expiry.sh` (rôle `expire_password()`, 6 tentatives avec le bon mot de passe → refus d'authentification sans « locked », `failed_attempts()` vide, connexion après rotation).
- (revue finale 3) G3 — un second verrou automatique posé alors que l'audit du premier était en attente écrasait `audit_locked_until` : le premier épisode disparaissait sans trace. Choix simple : pas de file, deux compteurs `audit_lock_seq` (épisodes posés) et `audit_acked_seq` (dernier épisode écrit) dans `pppRoleEntry` ; le worker écrit une ligne `role_locked` pour le dernier épisode avec `details.lost_episodes` = nombre d'épisodes antérieurs sans ligne (leur `locked_until` est perdu, leur nombre non), compté aussi dans `pseudo_locks` pour les noms inexistants ; l'acquittement compare `audit_lock_seq` et non plus `audit_locked_until` (deux verrous `DT_NOEND` successifs étaient confondus). Test : `standby.sh` (verrou local levé par `shmem_unlock_role()`, second verrou local, promotion → `lost_episodes = 1`).
- (revue finale 3) G4 — étape a de `run_maintenance()` : le DELETE des lignes `password_history` à `role_oid IS NULL` supprimait l'historique d'un `CREATE ROLE … PASSWORD` validé entre a0 et ce DELETE (READ COMMITTED : nouvel instantané par instruction). Seules sont purgées les lignes sans OID dont aucun rôle ne porte le nom ; les autres sont rattachées à la passe suivante. Test : `70_maintenance` (ligne sans OID d'un rôle existant rattachée, celle d'un nom inexistant purgée ; la fenêtre de course elle-même n'est pas reproduite en pg_regress).
- (revue finale 3) G5 — collision d'OID après restauration dans un autre cluster : l'ancien OID d'un rôle X peut appartenir à Y, et la passe de renommage de a0 réétiquetait les lignes de X au nom de Y. a0 n'est **pas** modifiée (S3 maintenu : dans un cluster vivant les OID sont stables, un couple « OID existant, autre nom » est un renommage et l'OID l'emporte ; une collision en est indiscernable). Chemin explicite : `rebind_restored_roles()` (SECURITY DEFINER, `_require_admin()` puis superutilisateur exigé, aucun GRANT, même verrou consultatif que `run_maintenance()`) rattache par nom toute ligne de `role_state`, `role_profile` et `password_history` dont le couple (`role_oid`, `role_name`) ne correspond à aucune ligne `pg_authid` (nom existant sous un autre OID → `rebind` ; nom inexistant → `purge` ; OID cible déjà pourvu d'une ligne correcte → `purge`, la ligne correcte gagne). Pour les tables à clé `role_oid`, toutes les lignes concernées sont d'abord supprimées (`DELETE … RETURNING`, gardées dans un tableau jsonb) puis réinsérées (`INSERT … ON CONFLICT DO NOTHING`) : deux lignes qui échangent leurs OID sont traitées quel que soit l'ordre (deux instructions plutôt qu'une : dans une seule, l'INSERT consommerait le DELETE ligne à ligne et l'ordre compterait de nouveau). `rotation_pair` ne porte que des noms : rien à rattacher. Une ligne `maintenance` (`details.rebind_restored_roles`) est écrite et la shmem rechargée si quelque chose a changé. Limite : une ligne restée sous un ancien nom (renommage non encore traité par une passe dans le cluster source) est purgée. Procédure dans le README (restauration : `enabled = off` et `worker_interval = 0`, `pg_restore`, `rebind_restored_roles()`, puis réactivation). Test : `70_maintenance` (échange des OID de deux rôles par UPDATE direct, lignes d'un rôle absent ; verrou, profil et historique rattachés, seconde passe vide, `run_maintenance()` ne défait rien ; test S3 inchangé) et `90_privileges` (refus pour `pass_policy_admin`).
- (revue finale 3) G6 — `ppp_sync_reload()` réinjectait un verrou depuis `role_state` sans poser `lock_set_at`, contrairement à l'en-tête de `pg_pass_policy.h` : `lock_set_at = now` quand la réinjection change `locked_until` (inchangé, l'horodatage d'origine est gardé). `v_role_status` : `nullif(greatest(…), '-infinity')` mort (aucune valeur `-infinity` possible, `greatest` ignore les NULL) simplifié en `greatest(…)`.
- (revue finale 3) G7 — l'upsert `role_state` de l'étape d'audit en attente écrivait sans condition les valeurs copiées sous LWLock : un `lock_role()` / `unlock_role()` validé entre la copie et l'upsert (ou dont l'upsert attendait le verrou de ligne) était écrasé (`locked_by = 'auto'`), puis le rechargement du même tour recopiait la valeur en shmem (`lock_seq` de l'admin ≤ `seq_snap`) : un verrou manuel `infinity` redevenait un verrou automatique qui expire, ou un déverrouillage était annulé. `pppPendingRow` mémorise `lock_seq` ; après les upserts et avant le COMMIT, l'étape relit sous le LWLock chaque entrée écrite : `lock_seq` différent, `lock_inflight` non nul ou entrée disparue → ERROR (WARNING « lock of role … changed while its automatic lock was being written »), transaction annulée, rien d'acquitté, nouvel essai au tour suivant (qui voit alors `locked_until ≠ audit_locked_until` : audit `lifted_before_audit`, pas d'upsert). Sûr : un `lock_role()` / `unlock_role()` validé a estampillé `lock_seq` dans son callback `XACT_EVENT_COMMIT`, avant de relâcher ses verrous (`CallXactCallbacks` précède `ResourceOwnerRelease` des verrous). `locked_until` n'est pas comparé : le seul autre écrivain pendant l'étape est le hook (nouvel épisode, qui reste en attente et sera écrit au tour suivant). Test : `lockout.sh` (transaction `lock_role()` ouverte 6 s, 3 échecs pendant ce temps, l'upsert du worker attend la ligne : après deux tours, `role_state` / `v_locked` = `manual` / `infinity`, shmem `infinity`, un seul `role_locked` auto).
- (revue finale 4) H1 — documentation : sous saturation du hash, le pseudo-verrou d'un nom inexistant (`GHOST`, toujours évincable) disparaît alors que le verrou d'un vrai rôle (`KEEP`) reste ; une nouvelle tentative répond alors « authentication failed » au lieu de « locked ». Oracle d'énumération résiduel, au prix d'environ `max_tracked_roles` connexions après le verrou. Compromis assumé (des pseudo-verrous non évincables permettraient de remplir le hash avec des noms inventés) : l'oracle est atténué, pas éliminé, il exige de saturer le hash. §6.3 et README (avertissement « Énumération des rôles », ligne `max_tracked_roles` : valeur largement supérieure au nombre de rôles, avec une marge).
- (revue finale 4) H2 — `check_password()` décidait de l'historique et de `min_age` par « superutilisateur ou le rôle lui-même », le hook par `PPP_MAY_SET_PASSWORD_OF()` : même prédicat désormais (`caller_is_super || (rôle existant && (rôle == appelant || PPP_MAY_SET_PASSWORD_OF(appelant, rôle)))`, identifiant explicite lu avant l'élévation). Un admin qui peut changer le mot de passe du rôle voit donc les mêmes refus que son `ALTER ROLE`. Test : `90_privileges` (`admin_option_check_other` : membre de `pass_policy_admin` avec `CREATEROLE` et `ADMIN OPTION` sur `regress_target` → `PPP-030` sur PG 14-15 comme sur PG ≥ 16 ; `admin_check_other` sans droit sur le rôle → NULL, inchangé).
- (revue finale 4) H3 — le hook parcourait tout le hash sous LWLock exclusif à chaque échec une fois le hash plein (tant qu'une entrée évincable existait, `evict_failed_at` ne jouait pas). Mode COUNT borné à `PPP_EVICT_SCAN_LIMIT` = 256 entrées par tentative, avec reprise au bucket suivant (`ppp_shared->evict_scan_bucket`) ; fenêtre infructueuse = « pas de place » sans LOG ; `evict_failed_at` posé quand les fenêtres infructueuses ont couvert tout le hash (`evict_scan_fruitless` ≥ nombre d'entrées), ce qui garde le comportement précédent pour un petit hash (≤ 256 entrées : une fenêtre = tout le hash). Écart assumé à la consigne (« fenêtre vide → `evict_failed_at` ») : poser le délai d'une seconde dès la première fenêtre vide ferait attendre jusqu'à `max_tracked_roles / 256` secondes avant de trouver une entrée évincable située plus loin. La reprise écrit `HASH_SEQ_STATUS.curBucket` après `hash_seq_init()` : structure déclarée opaque, mais champs et lecture par `hash_seq_search()` identiques dans 13.2, 16.4, 17beta1 et 18 (`hasHashvalue`, ajouté en 18, est mis à false par `hash_seq_init()`) ; un `curBucket` au-delà de `max_bucket` termine simplement le parcours, qui repart du bucket 0. Le mode PRIORITY garde le parcours complet. Test : `hashfull.sh`, scénarios existants inchangés (16 entrées : une fenêtre = tout le hash) ; ajout (redémarrage à `max_tracked_roles = 600`, extension recréée) : un seul nom inexistant, choisi dans un des derniers buckets (`hashtext(nom COLLATE "C") & 1023`, même hachage que `HASH_STRINGS`), et 599 verrous ; l'échec d'un vrai rôle n'est compté qu'à la 2e ou 3e tentative (fenêtre par fenêtre ; 1re tentative avec l'ancien parcours complet), sans LOG « cannot track » ; puis hash plein non évincable : un seul LOG « cannot track », une fois le hash parcouru.
- (revue finale 4) H4 — limite documentée de l'étape b de `run_maintenance()` : avec `verifier_pending`, un vrai changement fait hors du hook (`enforce_database = off` hors de la base, `enabled = off`, rôle exempté) entre un changement passé par le hook et la passe suivante est pris pour l'écart de sel attendu (historique mis à jour, sans audit ni nouvelle date de changement). Pas de correction : sans le mot de passe en clair, deux vérificateurs SCRAM de sels différents ne se comparent pas ; comparer les `xmin` de `pg_authid` et de `role_state` serait faux dès qu'une autre commande modifie l'une des deux lignes (`VALID UNTIL`, `lock_role()`…), avec le risque inverse (date de changement repoussée sans changement). README (avertissement `enforce_database = off`, `enabled = off` ou rôle exempté) et commentaire SQL.
- (revue finale 4) H5 — `failed_attempts()` et `ppp_sync_pending()` allouaient `max_tracked_roles` lignes à chaque appel : `ppp_alloc_hash_copy()` (`lockout.c`) lit `hash_get_num_entries()` sous verrou partagé, alloue ce nombre + `PPP_HASH_COPY_MARGIN` (16) lignes, reprend le verrou et recommence si le hash a dépassé cette taille entre-temps ; la copie reste bornée par la taille allouée.
- (revue finale 4) H6 — la copie de `ppp_sync_pending()` ne fait que lire (aucune écriture dans la boucle, l'acquittement est fait à part par `ppp_ack_pending()` après le COMMIT) : `LW_SHARED` au lieu de `LW_EXCLUSIVE`.
- (revue finale 4) H7 — la demande de `shmem_reload()` (`ppp_reload_in_xact`, booléen) survivait à un `ROLLBACK TO SAVEPOINT`, contrairement à son commentaire et aux autres demandes différées. Remplacée par `ppp_reload_subxid` : sous-transaction propriétaire, transmise au parent par `SUBXACT_EVENT_COMMIT_SUB`, effacée par `SUBXACT_EVENT_ABORT_SUB` (traité avant le test « aucune écriture en file » du callback). Le propriétaire est toujours la sous-transaction courante ou un de ses ancêtres : un second appel garde celui déjà enregistré. Test : `lockout.sh` (worker à 600 s : `shmem_reload()` puis `ROLLBACK TO SAVEPOINT` → `last_reload` inchangé après 3 s ; avec `RELEASE SAVEPOINT` → worker réveillé au COMMIT).
- (revue finale 4) H8 — `rotate_password()` et `switch_rotation_pair()` dupliquaient génération, `_set_password()`, `_ensure_recorded()`, `_refresh_role_state()` et la règle `VALID UNTIL` : fonction interne `_rotate_role(p_role name, p_oid oid, p_length int) RETURNS text` (*modifié* en (revue finale 5) K5 : `OUT password text, OUT profile text`) (plpgsql, `SET search_path`, ni `SECURITY DEFINER` ni GRANT : appelée seulement depuis ces deux fonctions `SECURITY DEFINER`, après `_require_admin()` et `_require_target_allowed()`). Dans `switch_rotation_pair()`, la mise à jour de `rotation_pair` précède désormais la génération (une ERROR annule tout de même la transaction).
- (revue finale 4) H9 — `ppp_audit_rejection()` ouvrait une sous-transaction pour un `audit()` (INSERT + NOTIFY) toujours annulé par l'ERROR qui suit. Supprimée : `ppp_reject()` écrit directement une ligne `ereport(LOG)` `pg_pass_policy: password_rejected role=<rôle> {"code": "PPP-0xx"}` (format de la ligne LOG de `_audit()`, `errhidestmt`/`errhidecontext`, si `log_events`), plus de SPI ni de sous-transaction ; `PPP-003` passe par le même chemin. `audit()` n'accepte plus l'appel « depuis le hook » (`_in_password_hook()`), devenu inutile : administrateurs seulement. §4, §6.2 et README mis à jour. Test : `notify.sh` (trois refus `PPP-010`, ligne LOG exacte).
- (revue finale 5) K1 — `unlock_role()` ne passait pas par `_ensure_state()` : pour un rôle sans ligne `role_state` (verrou automatique pas encore écrit par le worker), son UPDATE ne touchait aucune ligne et ne prenait aucun verrou de ligne ; l'upsert de `ppp_sync_pending()` pouvait alors valider le verrou périmé après le déverrouillage (la vérification de `lock_seq` avant le COMMIT du worker passait si le déverrouillage validait juste après), et le rechargement suivant reverrouillait le rôle. `unlock_role()` appelle désormais `_ensure_state()` comme `lock_role()` et `expire_password()` (qui le faisait déjà) : la ligne, insérée ou verrouillée, ordonne l'upsert du worker, qui attend la fin de la transaction et voit le `lock_seq` estampillé au COMMIT (avant la libération du verrou de ligne) ; ou bien `unlock_role()` attend l'upsert du worker et écrase son verrou. Test : `lockout.sh` (worker à 600 s, ligne `role_state` supprimée, verrou automatique, `unlock_role()` crée la ligne non verrouillée ; après le tour du worker : connexion acceptée, `role_state` non verrouillé, aucun verrou réinjecté, `role_locked` avec `lifted_before_audit`). La course elle-même n'est pas reproductible à coup sûr.
- (revue finale 5) K2 — l'étape f de `run_maintenance()` (`shmem_unlock_role(…, expired_only)`) effaçait en shmem `locked_until` d'un verrou expiré, y compris d'un verrou automatique plus récent que celui de `role_state`, expiré mais encore en attente d'audit : l'invariant de `ppp_expire_lock()` était cassé et la ligne `role_locked` portait à tort `lifted_before_audit`. En mode `expired_only`, le verrou expiré est confié à `ppp_expire_lock(entry, now, true)` (conservé tant que `lock_pending_audit`, compteurs de l'épisode remis à zéro, entrée estampillée si `locked_until` est effacé) ; `ppp_unlock_allowed()` ne laisse passer qu'un verrou expiré dans ce mode. Test : `lockout.sh` (premier verrou copié dans `role_state` puis expiré, second verrou posé et expiré worker endormi, `_shmem('unlock_expired')` puis `run_maintenance()` : le second `role_locked` n'a pas `lifted_before_audit` et le verrou expiré est copié dans `role_state`, levé par la passe suivante). Vérifié en retirant la correction : ces deux contrôles échouent.
- (revue finale 5) K3 — avec `pg_pass_policy.enabled = off`, seul `run_maintenance()` était sauté : `ppp_sync_pending()` écrivait encore audit et `role_state`, et le rechargement réinjectait, alors que la description du GUC et le README promettaient « le worker ne modifie rien ». Décision : `enabled = off` suspend tout le tour du worker (§5, §6.4) ; les entrées en attente restent en shmem jusqu'à la réactivation, dont le premier tour force un rechargement. Procédure de restauration du README mise à jour (`worker_interval = 0` n'est plus nécessaire pour le worker, seulement pour suspendre un `run_maintenance()` planifié ailleurs). Test : `lockout.sh` (échec en attente, `enabled = off` : ni audit, ni tour, ni rechargement malgré SIGHUP et `shmem_reload()`, un seul LOG « worker suspended » ; retour à `on` : échec journalisé, LOG « worker resumed »).
- (revue finale 5) K4 — `shmem_reload()` ne vérifiait pas `superuser()`, contrairement aux autres `shmem_*` : `ppp_require_superuser("shmem_reload")` ajouté (défense en profondeur : `EXECUTE` n'est accordé à personne, tous les appelants SQL sont `SECURITY DEFINER`).
- (revue finale 5) K5 — `rotate_password()` relisait `effective_profile()` après `_rotate_role()` pour le seul nom du profil de l'audit : un `assign_profile()` concurrent pouvait faire journaliser un autre profil que celui utilisé pour générer le mot de passe. `_rotate_role()` renvoie `OUT password text, OUT profile text` : une seule lecture, audit cohérent ; `switch_rotation_pair()` ne lit que `password`.
- (revue finale 6) Sécurité (Medium) — fenêtre d'ouverture au démarrage : le hash shmem est vide après un démarrage du postmaster, et le premier tour du worker exécutait `run_maintenance()` (passe complète, plus l'attente du verrou consultatif si pg_cron tourne) et l'étape d'audit **avant** `ppp_sync_reload()`, qui réinjecte `role_state.locked_until`. Pendant cette fenêtre, tout rôle verrouillé (verrou manuel `infinity` d'un compte compromis compris) pouvait s'authentifier, et la session obtenue survivait à la réinjection. Corrections : (1) `ppp_sync_first` (`worker.c`) : au premier tour, après promotion et après le retour de `enabled` à `on`, nettoyage + rechargement forcé d'abord, maintenance et audit ensuite (§6.4) ; (2) fail-closed dans le hook : nouveaux champs `pppSharedState.locks_loaded` et `not_loaded_logged_at` ; tant que `locks_loaded` est faux, les rôles non exemptés authentifiés par une méthode à secret reçoivent `FATAL 57P03` « pg_pass_policy: lock state not loaded yet, retry », bon ou mauvais mot de passe, avec un LOG au plus une fois par seconde ; `locks_loaded` est posé par `ppp_sync_reload()` ou quand l'extension est absente de `pg_pass_policy.database` (`PPP_EXT_ABSENT`, rien à réinjecter) ; `enabled = off` ne bloque pas (hook inactif), `worker_interval = 0` fait un premier tour de synchronisation au démarrage (vérifié, comportement existant), le tour standby recharge à chaque tour. Les rôles de `exempt_roles` et les méthodes sans secret passent toujours (§6.3, « Démarrage »). Tests : `lockout.sh` (verrou manuel, redémarrage avec `worker_interval = 0` puis connexion immédiate refusée, « locked » après le premier tour ; fenêtre tenue ouverte en renommant `role_state` : 57P03 pour le bon et le mauvais mot de passe, rôle exempté accepté, LOG limité, « locked » une fois `role_state` rétablie), `standby.sh` (`last_reload` posé par le premier tour standby) ; `common.sh` attend le premier rechargement après `CREATE EXTENSION`.
- (revue finale 7) Fenêtre fail-closed du démarrage, sept constats. (1) `worker_interval = 0` : un échec du premier rechargement n'était jamais retenté (`WaitLatch` sans délai), la fenêtre restait fermée jusqu'au prochain SIGHUP ; tant que `locks_loaded` est faux, ou qu'un rechargement est en attente avec `worker_interval = 0`, le worker se réveille au plus `PPP_RETRY_SECS` (5 s) plus tard. (2) `ppp_sync_reload()` posait `locks_loaded` même quand des verrous de `role_state` n'avaient pas trouvé de place dans le hash : il ne le pose plus que si tous les verrous sont réinjectés (un profil sans place ne retient pas la fenêtre), sinon LOG « persisted locks could not be loaded in shared memory: connections stay refused » et nouvelle tentative au tour suivant (`ppp_sync_reload()` renvoie faux, la demande reste en attente). (3) Extension absente : `ppp_sync_first` ne s'effaçait jamais, d'où deux transactions de synchronisation par tour ; `PPP_EXT_ABSENT` vaut désormais « rien à recharger » (`ppp_reload_pending` et `ppp_sync_first` effacés, `locks_loaded` posé). (4) La ligne `role_locked` d'un verrou automatique remplacé par un `lock_role()` avant le passage du worker portait `lifted_before_audit` : la copie retient `ppp_is_locked()` ; entrée encore verrouillée → `details.replaced_by_manual = true`, entrée non verrouillée → `lifted_before_audit`. (5) `ppp_extension_installed()` était du code mort : supprimée (prototype compris) ; le commentaire de `pg_pass_policy.h` renvoie à `ppp_require_extension()` / `ppp_extension_state()`. (6) Pendant la fenêtre, un échec était compté (et pouvait verrouiller) alors que le client recevait « retry » quel que soit le mot de passe, et un succès remettait le compteur à zéro (oracle : « 4 mauvais + candidat + mauvais » puis « locked » ou non à la sortie de la fenêtre) : l'entrée n'est plus modifiée tant que le rôle reçoit le `57P03` (`not_loaded` évalué juste après `ppp_is_locked()`, le refus d'un rôle déjà verrouillé en shmem gardant la priorité). (7) Sécurité/disponibilité : un worker qui ne démarre jamais (`max_worker_processes` épuisé, base inexistante) laissait, avec `exempt_roles` vide par défaut, une installation neuve refuser toutes les connexions par mot de passe, `postgres` compris ; les superutilisateurs (`rolsuper`, lu par la recherche syscache du hook) ne reçoivent plus le `57P03` (vraie réponse, échecs comptés, FATAL « locked » si un verrou est en shmem), et le hook émet un WARNING « pg_pass_policy worker has not loaded the lock state yet (worker_pid = 0) », HINT `max_worker_processes` / `pg_pass_policy.database`, au plus une fois par minute, 10 s après l'initialisation de la shmem (`shmem_init_at`, `worker_missing_logged_at`). Tests : `lockout.sh` (fenêtre tenue avec `worker_interval = 0` : rechargement retenté sans SIGHUP après le retour de `role_state` ; « 4 mauvais + bon + mauvais » toujours `57P03`, `failed_attempts()` vide, rôle accepté après la fenêtre ; superutilisateur non exempté accepté pendant la fenêtre, refus normal sur mauvais mot de passe ; `pg_pass_policy.database` inexistante : superutilisateur accepté, rôle ordinaire `57P03`, WARNING une seule fois, superutilisateur verrouillé en shmem après 5 échecs), `hashfull.sh` (verrou automatique remplacé par `lock_role()` : `replaced_by_manual` sans `lifted_before_audit` ; 599 verrous persistés pour `max_tracked_roles = 16` : LOG répété, fenêtre maintenue, connexion acceptée une fois les verrous levés dans `role_state`, sans SIGHUP).
- (revue finale 8) Fenêtre de démarrage, neuf constats. (1) Sécurité : le message « worker has not loaded the lock state yet (worker_pid = 0) » était un `WARNING` émis depuis le hook d'authentification. PostgreSQL ne l'envoyait pas au client (`should_output_to_client()` ne laisse passer que ERROR et plus tant que `ClientAuthInProgress`, vérifié dans 16.4), mais rien dans le code ne le garantissait : il est désormais `LOG`, avec `PPP_LOG_PREFIX`, comme les autres messages du hook (seuls les FATAL de refus dépassent `LOG`) ; le DETAIL du FATAL `57P03`, lui envoyé au client, ne nomme plus le worker (« The server has just started; retry in a few seconds. »), et les HINT des LOG ne disent plus que les superutilisateurs passent toujours. (2) Sécurité : l'exception superutilisateur de la revue finale 7 retirait la garantie fail-closed pour un superutilisateur verrouillé à la main pendant toute fenêtre de démarrage et créait un oracle « nom de superutilisateur » ; elle ne s'applique plus que worker démontrablement absent (`worker_pid = 0` plus de `PPP_WORKER_MISSING_GRACE_SECS` après `shmem_init_at`, la condition du LOG « worker missing ») ; pendant un démarrage normal les superutilisateurs reçoivent le `57P03` comme les autres. (3) Standby : le test `RecoveryInProgress()` précédait la relance, si bien qu'un premier rechargement en échec sur un standby attendait `worker_interval` ; la relance de 5 s est évaluée d'abord. (4) Extension non fiable (`PPP_EXT_UNTRUSTED`) : journalisée en DEBUG1 avec le texte « not installed » alors que la fenêtre restait fermée sans trace ; `WARNING` au plus une fois par minute, DETAIL du propriétaire du schéma (`ppp_untrusted_detail()`, partagé avec PPP-004). (5) Fenêtre maintenue ouverte : chaque relance de 5 s exécutait tout le tour (maintenance, audit, deux synchronisations) ; tant que `ppp_sync_first` est posé, une relance (réveil sur délai, sans demande ni SIGHUP, moins de `worker_interval` après le dernier tour complet) s'arrête après la synchronisation en échec ; le LOG « persisted locks could not be loaded » est limité à une fois par minute. (6) `replaced_by_manual` était déduit de `ppp_is_locked()` : un verrou manuel de remplacement déjà expiré au passage du worker était audité `lifted_before_audit` ; il l'est d'après `locked_until != 0` (et `!= audit_locked_until`). (7) `worker_status()` expose `locks_loaded bool` (5 colonnes, `expected_natts` 5) ; le CLI (`cli/src/commands.rs`) et le web (`web/app/db.py`) nomment leurs colonnes, l'ajout ne les touche pas. (8) Les deux limiteurs « une fois par N s » du hook (`not_loaded_logged_at`, `worker_missing_logged_at`) et ceux du worker passent par `ppp_log_due()` (`pg_pass_policy.h`). (9) Délai de relance : `(ppp_worker_interval > 0 ? Min(ppp_worker_interval, PPP_RETRY_SECS) : PPP_RETRY_SECS) * 1000L` au lieu de deux `Min` imbriqués. Tests : `lockout.sh` (fenêtre, worker présent : superutilisateur non exempté refusé `57P03` au bon comme au mauvais mot de passe, sortie du client sans « worker » ni « exempt », `locks_loaded` faux puis vrai, relances limitées à la synchronisation : `last_run` inchangé ; base inexistante : superutilisateur refusé avant 10 s, accepté ensuite, LOG et plus de WARNING ; schéma cédé à un non-superutilisateur : WARNING une fois avec le propriétaire, fenêtre fermée puis rouverte), `hashfull.sh` (verrou manuel d'une seconde expiré avant le worker : `replaced_by_manual` sans `lifted_before_audit`, échoue sans la correction ; LOG « persisted locks » une seule fois), `standby.sh` (premier rechargement du standby en échec avec `worker_interval = 3600`, retenté en 5 s une fois `role_state` rétablie, échoue sans la correction), `00_setup` (colonnes de `worker_status()`).
- (revue finale 7, point 8) `generate_password()` levait « could not generate a password compliant with profile … » en `XX000` (erreur interne), que le web traite en 500. Seul `PPP-019` (`max_repeat`) peut réellement épuiser les `PPP_GEN_MAX_TRIES` tirages : longueur et minima de classes sont vérifiés avant (`22023`), la composition des classes est garantie par construction et l'alphabet spécial ne contient pas d'espace (`PPP-020`). Ce cas (minima qui imposent beaucoup de caractères d'une petite classe avec un `max_repeat` bas) est un profil irréalisable en pratique : `22023` (`ERRCODE_INVALID_PARAMETER_VALUE`), avec DETAIL et HINT ; tout autre code reste `XX000` (défaut du générateur). Test : `40_generate` (200 chiffres sur 203 caractères, `max_repeat = 1` → `22023`).
- (clôture) Neuf constats. (1) `_rotate_role()` générait 24 caractères par défaut : `rotate_password()` / `switch_rotation_pair()` échouaient (`22023`) pour un profil dont `min_length > 24`. Le paramètre `length` vaut désormais NULL par défaut : longueur `least(greatest(24, min_length), max_length)` ; une longueur explicite hors de `[min_length, max_length]` est refusée en `22023` avec DETAIL et HINT ; l'audit `password_rotated` porte la longueur réelle. Test : `50_rotation` (profil `min_length = 32` → 32 caractères ; 24 et 41 refusés ; `max_length = 16` → 16). (2) L'assign hook de `exempt_roles` appelait `SplitIdentifierString()` (palloc : ERROR possible en mémoire saturée, y compris dans le postmaster). Le découpage est fait par le check hook, qui a le droit de lever ; il construit un bloc unique `pppExemptList` (noms recopiés dans le même bloc) rendu par `*extra`, alloué par `PPP_GUC_MALLOC` (`compat.h` : `guc_malloc(LOG, …)` à partir de PG 16, `malloc()` avant) ; l'assign hook ne fait que recopier le pointeur, le contexte privé `ppp_exempt_cxt` (C10) est supprimé. Test : `lockout.sh` (liste invalide refusée par `ALTER SYSTEM`, nom entre guillemets à casse conservée, tests existants sur `regress_exempt`, au redémarrage compris). (3) `PPP-020` ne voyait que les contrôles ASCII : U+200B, U+0085, U+00A0… comptaient comme « special ». Dans une base UTF8, le point de code est décodé (décodage UTF-8 local, sans dépendance de version) et comparé à une table explicite triée (catégories Cc, Cf, Zs hors U+0020, Zl, Zp d'Unicode 15, recherche dichotomique, sans ICU) ; les autres encodages gardent le comportement antérieur. Test : `unicode.sh` (U+200B, U+0085, U+00A0, U+2028, U+FEFF, U+3000 refusés par `check_password()`, U+200B par `ALTER ROLE` ; lettres accentuées acceptées). (4) `drop_profile()` comptait les lignes `role_profile` de rôles supprimés : elles sont purgées sur place avant le comptage. Test : `10_profile` (`regress_ghost` supprimé, profil supprimable, ligne purgée). (5) Clés `details` alignées sur le worker : `role_locked` de `lock_role()` porte `locked_by` / `locked_until` (au lieu de `by` / `until`), `role_unlocked` porte `unlocked_by` (`manual` ou `auto`). Tests : `70_maintenance`, `hashfull.sh`, `lockout.sh` ; README. (6) `ppp_worker_on_exit()` écrivait `worker_pid` sans le LWLock : `worker_pid` devient un `pg_atomic_uint32`, lu partout par `ppp_get_worker_pid()` et effacé à la sortie par compare-and-exchange (seulement s'il porte encore notre PID). Choix fait ici plutôt que `LWLockConditionalAcquire()` : le callback peut tourner après un FATAL levé sous le verrou, et l'atomique n'a besoin d'aucun repli. (7) L'étape f de `run_maintenance()` auditait `role_unlocked` même quand la shmem refusait le déverrouillage (verrou automatique plus récent). `shmem_unlock_role()` renvoie désormais un booléen : avec `expired_only`, false (et rien n'est différé) si l'entrée porte un verrou actif au moment de l'appel ; `_shmem('unlock_expired')` le relaie et l'étape f n'audite ni ne renvoie l'action que s'il est vrai (`role_state` est tout de même nettoyé du verrou expiré, le worker y recopie le nouveau). Un verrou posé entre l'appel et le COMMIT reste conservé au COMMIT (LOG existant) : la réponse est alors optimiste. Test : `lockout.sh` F4 (aucune action ni audit `role_unlocked`, `role_state` sans le verrou expiré ; K2 inchangé : le verrou expiré en attente d'audit est levé et audité). (8) `_ensure_recorded()` devinait que le hook avait enregistré (`password_changed_at = now() AND verifier_pending`). Nouvelle fonction C `_record_done(role name) RETURNS bool` (`ppp_record_done`) : vrai si le hook a enregistré un changement de ce rôle dans la transaction courante ; drapeau local au backend (`ppp_note_password_recorded()` après `record_password_change()`), effacé au COMMIT, à l'ABORT et au PREPARE par le XactCallback de `lockout.c`, transmis au parent ou effacé avec sa sous-transaction (comme la demande de rechargement). Écart avec la demande initiale (`_record_done()` sans argument) : le nom du rôle évite qu'un changement enregistré pour un autre rôle dans la même transaction dispense d'enregistrer un rôle exempté. Limite : deux changements du même rôle dans une transaction, le premier par le hook et le second hors hook (rechargement de configuration entre les deux), ne donnent qu'une ligne d'historique. Tests : `50_rotation` (drapeau faux avant, vrai après la rotation, faux pour un autre rôle, après COMMIT et après `ROLLBACK TO SAVEPOINT` ; une ligne d'historique et un audit par rotation), `lockout.sh` (rôle exempté : `rotate_password()` enregistré par `_ensure_recorded()`). (9) `ppp_getint()` (worker) et `ppp_get_int()` (policy) dupliquaient la lecture d'un int4 SPI : helper partagé `ppp_spi_get_int32()` dans `pg_pass_policy.c`.
- (vérification) Sept constats. (1) `_rotate_role()` : la longueur par défaut `least(greatest(24, min_length), max_length)` ignorait la somme des minima de classes ; un profil `min_digit = 30` faisait échouer `rotate_password()` en `22023`. Défaut : `least(greatest(24, min_length, min_lower + min_upper + min_digit + min_special), max_length)`. La contrainte `profile_classes_fit` (somme des minima ≤ `max_length`, déjà présente, refusée en `23514` par `create_profile()` / `alter_profile()`) calcule désormais la somme en bigint (quatre grands minima débordaient int4 en `22003`). Tests : `10_profile`, `50_rotation` (`min_digit = 30` → 33 caractères dont au moins 30 chiffres ; `min_digit = 61` accepté avec `max_length = 64`, 62 refusé, rotation à 64). (2) `ppp_sync_reload()` lisait `role_profile` avec `LEFT JOIN pg_roles` : la ligne d'un rôle supprimé, pas encore purgée par `run_maintenance()` (jamais avec `worker_interval = 0`, ni au premier rechargement d'un démarrage), donnait à l'ancien nom une entrée `from_profile` (`KEEP`, jamais évincée). Jointure interne : seuls les rôles existants reçoivent un profil, `pppProfileRow.role_exists` disparaît. Test : `lockout.sh` (`worker_interval = 0`, profil assigné puis `DROP ROLE` : ligne `role_profile` encore là, `tracked_roles` revenu à sa valeur initiale après deux rechargements). (3) `ppp_ack_pending()` recopiait `audit_lock_seq` de la copie dans `audit_acked_seq` même si l'entrée avait été évincée puis recréée entre la copie et l'acquittement (numérotation repartie de 0) : `audit_acked_seq` passait devant `audit_lock_seq` et la différence non signée donnait environ quatre milliards de `lost_episodes`. L'acquittement n'a lieu que si `entry->audit_lock_seq` est au moins celui de la copie (différence signée) et, à numéro égal, pour le même `audit_locked_until` ; sinon l'entrée est laissée telle quelle (échecs et verrou réécrits au tour suivant). `lost_episodes` est calculé en différence signée, borné à 0. Limite : une entrée recréée sans aucun verrou (numéro 0 des deux côtés) ne se distingue pas de l'ancienne, ses `pending_failures` sont décomptés comme avant. (4) `evict_scan_fruitless` additionnait les entrées examinées par les fenêtres infructueuses du mode COUNT ; la reprise au début du bucket interrompu en milieu de chaîne recomptait des entrées, et le seuil « nombre d'entrées » pouvait être atteint avant un tour réel. Le suivi se fait en positions de bucket (`evict_fruitless_from`, `evict_fruitless_wrapped`, `evict_fruitless_active` remplacent `evict_scan_fruitless`) : `evict_failed_at` n'est posé que lorsque la série, après être passée par le dernier bucket, revient au bucket où elle a commencé (ou qu'un seul parcours a fait le tour). Une série qui démarre au-delà du dernier bucket non vide repart du bucket 0. Test : `hashfull.sh` inchangé (600 entrées, un seul fantôme dans un des derniers buckets). (5) L'upsert `role_state` d'un verrou automatique en attente joint `pg_roles` par le nom de la clé shmem : après `ALTER ROLE … RENAME` (ou `DROP ROLE`), rien n'était écrit, mais l'acquittement effaçait `lock_pending_audit` et la ligne `role_locked` laissait croire à un verrou persistant. Le worker vérifie d'abord l'existence du nom ; s'il n'existe plus, `role_locked` est écrit sous l'ancien nom avec `role_missing: true`, plus `role_renamed: true` et `renamed_to` quand une ligne `role_state` ou `role_profile` porte encore l'ancien nom d'un OID existant ; `role_state` n'est pas écrit, l'entrée devient fantôme (`role_missing`) à l'acquittement et sera purgée comme telle. Un rôle qui disparaît entre cette vérification et l'upsert (aucune ligne insérée) annule la transaction (ERROR, rien n'est acquitté, reprise au tour suivant). Écart assumé à la consigne (« ne pas acquitter, garder `lock_pending_audit` ») : garder l'attente réécrirait `role_locked` à chaque tour ; l'acquittement est sûr dès lors que la ligne d'audit dit explicitement que le verrou n'a pas été persisté. Le verrou n'est pas transféré au nouveau nom (§12). Test : `lockout.sh` (`worker_interval = 0` : verrou automatique, renommage avant le passage du worker, `role_locked` sous l'ancien nom avec `role_missing` / `role_renamed` / `renamed_to`, une seule ligne après deux tours, `role_state` non verrouillé, le nouveau nom se connecte). (6) `max_length` acceptait jusqu'à 1024 et `min_length` n'avait pas de borne haute, alors que `generate_password()` refuse plus de 512 caractères (`PPP_GEN_MAX_LENGTH`, `policy.c`) : `CHECK (min_length BETWEEN 8 AND 512)` et `CHECK (max_length <= 512)`, commentaire dans le script SQL pour garder les deux valeurs alignées. Test : `10_profile` (513 refusé pour l'un et l'autre en `23514`, 512 accepté). (7) `_is_admin()` appelait `pg_has_role(session_user, 'pass_policy_admin', 'MEMBER')` : une fois `pass_policy_admin` supprimé, l'appel levait « role does not exist » (`42704`), y compris pour un superutilisateur. Le rôle est cherché dans `pg_roles` et son OID passé à `pg_has_role()` (`EXISTS … AND pg_has_role(session_user, g.oid, 'MEMBER')`) ; `pass_policy_viewer` n'est testé par aucune fonction (droits par `GRANT`). Test : `90_privileges` (`pass_policy_admin` renommé dans une transaction annulée : `_is_admin()` vrai et `lock_role()` accepté pour le superutilisateur, ancien membre refusé en `42501`).
- (vérification 2) Sept constats. (1) `profile_classes_fit` et la longueur par défaut de `_rotate_role()` utilisaient la somme brute des minima ; `generate_password()` (`policy.c`) tire `Max(min_lower, 1) + Max(min_upper, 1) + Max(min_digit, 1) + min_special` caractères, plus un spécial quand `3 + (min_special > 0) < min_classes`. Un profil `min_digit = 30`, autres minima à 0, `min_classes = 3` donnait une longueur par défaut de 30 et `rotate_password()` échouait en `22023`. Nouvelle fonction `_generator_minimum(min_lower, min_upper, min_digit, min_special, min_classes) RETURNS int` (SQL, `IMMUTABLE`, corps SQL standard `RETURN` analysé à `CREATE EXTENSION` : le `search_path` de l'appelant n'intervient pas), même calcul que `policy.c`, en bigint plafonné à int4 (quatre grands minima donnent `23514` et non `22003`) ; utilisée directement par le `CHECK` `profile_classes_fit` (une fonction SQL immuable est acceptée dans un `CHECK` : pas besoin de trigger) et par `_rotate_role()`. Écart à la consigne : arguments scalaires plutôt qu'une ligne `profile` (une fonction prenant le type ligne de la table ne peut pas servir au `CHECK` de sa propre déclaration). La formule reste dupliquée entre C et SQL, commentaire dans les deux sens. Tests : `10_profile` (valeurs de `_generator_minimum()`, `max_length = 31` refusé pour 30 chiffres, 32 accepté, `min_classes = 4` refusé à 32 par `create_profile()` et `alter_profile()`), `50_rotation` (`min_digit = 30`, autres à 0 : rotation à 32 caractères ; `min_classes = 4` : 33 ; `max_length = 32` alors refusé en `23514`). (2) `ppp_ack_pending()` distinguait l'entrée copiée d'une entrée recréée par `audit_lock_seq` et `audit_locked_until` : deux verrous jusqu'au déverrouillage manuel (`DT_NOEND`) au même numéro d'épisode étaient confondus. Nouveau champ `pppRoleEntry.audit_lock_set_at` (posé par le hook avec `audit_locked_until`, recopié dans `pppPendingRow`), comparé en plus à numéro égal. Pas de test : il faudrait évincer puis recréer l'entrée et la reverrouiller entre la copie de `ppp_sync_pending()` et l'acquittement, fenêtre interne au worker qu'aucun test shell ne peut viser à coup sûr. (3) La série de parcours infructueux d'éviction (`evict_fruitless_active`) survivait à des changements du hash : elle est remise à zéro quand `ppp_enter_role()` crée une entrée sans parcours (hash pas plein), quand une éviction réussit quel que soit le mode (PRIORITY compris) et quand `ppp_sync_cleanup()` purge au moins une entrée. Test : `hashfull.sh` inchangé et vert. (4) Rôle renommé `a` → `b` puis `b` → `a` entre la recherche de `ppp_sync_pending()` et l'acquittement : l'entrée d'un rôle vivant, avec un verrou réel, devenait fantôme (évinçable). L'acquittement se fait hors transaction : `ppp_ack_pending()` lance, seulement si une ligne a `role_gone`, une courte transaction (`ppp_run_in_xact("role existence check")`) qui revérifie le nom dans le syscache (`SearchSysCacheExists1(AUTHNAME)`, hors du LWLock) ; `role_missing` n'est posé que si le rôle est toujours absent (`gone_confirmed`). Si la vérification échoue, l'entrée n'est pas rendue fantôme (choix prudent). Limite : la ligne `role_locked` déjà écrite garde `role_missing: true` et le verrou n'est pas recopié dans `role_state` (il vit en mémoire partagée jusqu'à son expiration). Pas de test dédié : il faudrait intercaler deux renommages dans un tour du worker, et `failed_attempts()` n'expose pas `role_missing` ; le test de renommage de `lockout.sh` (rôle toujours absent : fantôme, audit unique) reste vert. (5) La sous-requête `renamed_to` du worker est évaluée seulement si le rôle n'existe pas (`CASE WHEN NOT g.found`, `EXISTS` calculé une fois dans une sous-requête `OFFSET 0`). (6) Commentaires de `rotate_password()` / `switch_rotation_pair()` et HINT de `_rotate_role()` : la longueur par défaut est relevée au `min_length` et à la longueur qu'exigent les minima de classes. (7) La constante 512 n'apparaît plus qu'une fois côté SQL : `_max_generated_length()` (`IMMUTABLE`, `RETURN 512`) utilisée par `CHECK (max_length <= _max_generated_length())` ; `min_length` garde seulement `>= 8`, sa borne haute découle de `profile_length_range`. Test : `10_profile` inchangé (`min_length = 513` toujours refusé en `23514`, par `profile_length_range`).
- (vérification 3) Huit constats. (1) Les `CHECK` de `profile` appellent `_max_generated_length()` et `_generator_minimum()`, dont `EXECUTE` était retiré à `PUBLIC` par le `REVOKE` global : un `INSERT` / `UPDATE` direct ou un `pg_restore` par un non-superutilisateur échouait en `42501` au lieu d'être jugé par la contrainte. `GRANT EXECUTE … TO PUBLIC` sur ces fonctions pures (après le `REVOKE` global ; sans `USAGE` sur le schéma, un rôle ordinaire ne peut toujours pas les nommer). Nouvelle `_min_generated_length()` (`RETURN 8`, `PPP_GEN_MIN_LENGTH`) utilisée par `CHECK (min_length >= …)`, par symétrie avec la borne haute, accordée de même. Tests : `90_privileges` (`has_function_privilege()` vrai pour `regress_user` sur les trois, appel par `regress_viewer` ; `INSERT` direct par `regress_admin` après `GRANT INSERT, UPDATE` dans une transaction annulée : `min_length = 7`, `max_length = 513`, minima de classes trop grands et `UPDATE max_length = 513` donnent `23514`, une ligne valide passe). (2) Rôle trouvé absent par `ppp_sync_pending()` puis revenu à la revérification (`a` → `b` → `a`) : `lock_pending_audit` était effacé alors que `role_state` n'avait pas été écrit (le verrou ne vivait plus qu'en mémoire partagée). Si `role_gone && !gone_confirmed` (rôle revenu, ou revérification en échec), l'acquittement laisse le verrou en attente (ni `lock_pending_audit` effacé, ni `audit_acked_seq` avancé ; les échecs écrits sont décomptés) : le tour suivant écrit une ligne `role_locked` normale, qui complète la première (`role_missing`), et recopie le verrou dans `role_state` ; un rôle réellement parti est audité une seconde fois avec `role_missing`, puis devient fantôme. Pas de test : il faudrait intercaler deux renommages entre le COMMIT de l'étape d'audit et la transaction de revérification, fenêtre interne au worker qu'aucun test shell ne vise à coup sûr. (3) Un autre rôle créé sous l'ancien nom (`DROP ROLE` puis `CREATE ROLE`) héritait du verrou : la revérification ne comparait que le nom, et, recréé avant le passage du worker, le nouveau rôle recevait même la ligne `role_state` verrouillée. Le hook mémorise l'OID du rôle à la pose du verrou automatique (`pppRoleEntry.audit_role_oid`, lu dans le même accès au syscache que `rolvaliduntil`), recopié dans `pppPendingRow.role_oid`. Écart à la consigne (OID tiré de la requête de recherche du worker) : quand le rôle est recréé avant le tour, cette requête trouve déjà le nouveau rôle et ne peut pas le distinguer de l'ancien ; seul le hook connaît le rôle verrouillé. Le worker ne tient le rôle pour présent que si le nom mène à cet OID (OID inconnu : comparaison par nom seul, comme avant), l'upsert `role_state` est restreint à cet OID, `renamed_to` est lu par OID, et l'audit ajoute `role_recreated: true` quand le nom appartient à un autre rôle ; la revérification compare aussi l'OID et confirme l'absence (fantôme, évinçable) pour un autre rôle. Test : `lockout.sh` (`worker_interval = 0` : verrou automatique, `DROP ROLE` et `CREATE ROLE` du même nom dans une transaction, tour du worker : `role_locked` avec `role_missing` et `role_recreated`, sans `renamed_to`, une seule ligne après deux tours, aucun verrou dans `role_state`, plus de verrou dans `failed_attempts()` après expiration, le nouveau rôle se connecte). (4) La revérification passait par `ppp_run_in_xact()`, qui, extension absente, effaçait `ppp_reload_pending` / `ppp_sync_first` et ouvrait la fenêtre de démarrage (`locks_loaded`). Paramètre `pure` : la revérification l'appelle à vrai, ces drapeaux ne sont alors pas touchés ; les étapes du cycle passent faux. (5) `evict_failed_at` (pause d'une seconde après un tour infructueux) survivait aux changements du hash : remis à 0, comme `evict_fruitless_active`, quand `ppp_enter_role()` crée une entrée sans parcours, quand une éviction réussit et quand `ppp_sync_cleanup()` purge. Test : `hashfull.sh` inchangé et vert. (6) `ppp_ack_pending()` cherchait par une boucle si une ligne avait `role_gone` : drapeau `ppp_pending_any_gone`, posé par `ppp_sync_pending()` quand la recherche trouve le rôle absent, remis à faux à la copie et par `ppp_free_pending()`. (7) Commentaires de `50_rotation` (et de son `expected`) : la longueur par défaut et `profile_classes_fit` suivent `_generator_minimum()`, plus la somme des minima. (8) §3.1, §8 et §12 mis à jour.
- (vérification 4) Cinq constats. (1) Le hook n'appliquait `PPP-003` / `enforce_database` que si l'extension était **absente** de la base courante : une extension installée dans une autre base que `pg_pass_policy.database` était traitée comme fiable, et la politique écrivait dans des tables (`password_history`, `role_state`) que le worker ne maintient jamais. La base courante est désormais testée d'abord (`ppp_in_policy_database()`, `policy.c`) : hors de `pg_pass_policy.database`, même règle que pour l'absence (`PPP-003` si `enforce_database`, sinon WARNING une fois par session et politique non appliquée), extension installée ou non ; l'état de l'extension (`PPP-004`, absence) n'est lu que dans cette base. §5, §6.2 (étape 2) et README (une seule base) mis à jour. Test : `notify.sh` (`CREATE EXTENSION` dans `ppp_otherdb`, `ALTER ROLE` depuis cette base → `PPP-003`, puis `enforce_database = off` → WARNING ; aucun historique écrit dans les deux cas). (2) `ppp_ack_pending()` (`worker.c`) reconnaissait une entrée évincée puis recréée sous le même nom à ses numéros d'épisode ; avant tout verrou, les deux valent 0 et les `pending_failures` de la nouvelle entrée étaient décrémentées de celles de l'ancienne, perdues sans audit. Nouveau champ `pppRoleEntry.generation` (numéro d'incarnation, donné par `ppp_init_entry()` depuis `pppSharedState.entry_generation`, sous le verrou exclusif ; conservé par la restauration d'une victime au PRE_COMMIT, qui reste la même incarnation), copié dans `pppPendingRow` : une entrée d'une autre génération est laissée intacte, ses échecs sont audités au tour suivant. Les tests d'épisode restent en seconde garde. (3) `check_password()` sautait l'historique pour un rôle inexistant (`OidIsValid(roleid) && …`) alors que le hook le vérifie (`!OidIsValid(roleid) || …`, cas de `CREATE ROLE … PASSWORD`) : même prédicat désormais, l'historique par nom (lignes sans OID) est vérifié comme le fera `CREATE ROLE`. Corrige le prédicat retenu en revue finale 4 (H2) pour le rôle inexistant ; aucun oracle nouveau : ces lignes ne concernent aucun rôle existant. Test : `90_privileges` (`admin_check_missing_role` : `CREATE ROLE … PASSWORD` puis `DROP ROLE`, admin non superutilisateur → `PPP-031`). (4) `ppp_role_is_exempt()` (`pg_pass_policy.c`) gardait un repli qui redécoupait `exempt_roles` quand la liste de l'assign hook manquait, cas impossible (le check hook la construit pour toute valeur acceptée, valeur de démarrage comprise) : supprimé, remplacé par un `Assert` et un retour `false` (aucun rôle exempté, la politique s'applique). (5) `run_maintenance()` étape d appelait `_apply_valid_until()` pour chaque rôle à chaque passe : une seule requête ensembliste calcule la valeur cible (`least(grace_until, borne de paire)`, comme `_apply_valid_until()`) et ne retient que les rôles dont `rolvaliduntil` en diffère (`sync` : cible NULL → seul un `VALID UNTIL` fini est candidat ; `unblock` : `VALID UNTIL` passé et différent de sa cible). Ce filtre est une condition nécessaire de toute modification par la fonction, qui garde la décision finale (valeur manuelle plus courte, valeur non écrite par l'extension) ; tests `70_maintenance` inchangés.
- (vérification 5) Six constats. (1) `_apply_valid_until()` en mode `unblock` (rôle exempté ou `manage_valid_until = off`, appelé par `rotate_password()` et `switch_rotation_pair()` via `_rotate_role()`) relevait tout `VALID UNTIL` passé, y compris une date posée à la main pour désactiver le compte, alors que l'étape d de `run_maintenance()` exige `rolvaliduntil IS NOT DISTINCT FROM valid_until_synced`. La fonction applique désormais la même garde : seule une borne posée par l'extension (`expire_password()`, borne de paire, synchronisation antérieure) est relevée. Test : `90_privileges` (`exempt_manual_valid_until_kept`, `VALID UNTIL '2020-01-01'` conservé par `rotate_password()` puis par `run_maintenance()`). (2) `v_role_status` ignorait `exempt_roles` : un rôle exempté s'affichait `warning`, `grace` ou `expired` et figurait dans `v_expiring` alors qu'aucune expiration ne lui est appliquée. Nouveau statut `exempt` (`_is_exempt(rolname)`), placé juste après `locked` : il prime sur `grace`, `expired`, `never_expires`, `unknown`, `warning` et `ok` ; un verrou reste affiché `locked` (il s'applique de nouveau dès que le rôle quitte la liste, et `v_locked` doit continuer de le montrer). `v_expiring` exclut donc les rôles exemptés. `EXECUTE` sur `_is_exempt(text)` est accordé à `pass_policy_viewer` et `pass_policy_admin` : les fonctions d'une vue s'exécutent avec les droits de son utilisateur ; `exempt_roles` est de toute façon lisible par tous (`SHOW`). §4 et README mis à jour. Test : `90_privileges` (statut `exempt` après `expire_password()`, absent de `v_expiring`, lu par `regress_viewer`). (3) `unlock_role()` écrivait `role_unlocked` (audit et NOTIFY) même sans verrou. Il n'audite plus que si `role_state.locked_until` était non NULL (verrou expiré non encore nettoyé compris) ou si `failed_attempts()` montrait un verrou en mémoire partagée (verrou automatique pas encore recopié par le worker) ; sinon `NOTICE` « role "…" is not locked », sans audit. Écart avec la demande initiale (« ou si `shmem_unlock_role()` a renvoyé vrai ») : sans `expired_only`, `shmem_unlock_role()` renvoie toujours vrai et ne dit rien du verrou ; `failed_attempts()` est lu à la place. Le déverrouillage et la remise à zéro du compteur d'échecs sont toujours différés au COMMIT, verrou ou non. Test : `60_lock_unlock` (`unlock_again_not_audited`, `shmem_only_unlock_audited` après `shmem_lock_role()` seul). (4) `_dictionary_trg()` : un mot NULL inséré directement (`INSERT`, `COPY` ; `load_dictionary()` les filtrait déjà) faisait échouer toute l'instruction sur la contrainte NOT NULL de la clé primaire ; il est ignoré comme un mot vide (`RETURN NULL`). Test : `20_complexity` (`VALUES (NULL), ('  '), ('Null-Word-Test9')` : seul le troisième est inséré). (5) `_set_password()` restaurait explicitement `pg_stat_statements.track_utility` à la sortie normale et dans le gestionnaire d'erreur : restaurations inutiles, la clause `SET` de la fonction rétablit déjà les valeurs de l'appelant à la sortie ; supprimées, avec un commentaire. (6) Le test « `session_user` est-il superutilisateur » était écrit trois fois (`_is_admin()`, `_require_target_allowed()`, `rebind_restored_roles()`) : helper `_session_is_superuser() RETURNS bool` (`LANGUAGE sql STABLE`, aucun droit accordé).
- (vérification 6) Douze constats. (1) `v_role_status` : la priorité de `status` (`locked` > `exempt` > état d'expiration) masquait qu'un rôle verrouillé ou exempté est aussi expiré. `status` est conservé tel quel ; trois colonnes sont ajoutées **après** `role_oid` (ordre des colonnes existantes inchangé pour les clients) : `is_exempt` (bool), `expiry_state` (`ok | warning | grace | expired | never_expires | unknown`, calculé indépendamment du verrou et de l'exemption) et `valid_until` (`pg_roles.rolvaliduntil`). `v_expiring` filtre désormais sur `expiry_state IN ('warning', 'grace', 'expired') AND NOT is_exempt` : un rôle verrouillé et expiré y figure. §4 et README mis à jour. Test : `70_maintenance` (colonnes des quatre rôles de statut ; rôle expiré puis verrouillé : `status = locked`, `expiry_state = expired`, présent dans `v_expiring` et `v_locked`), `90_privileges` (rôle exempté : `status = exempt`, `expiry_state = expired`, `valid_until`, lus aussi par `regress_viewer`). (2) `expire_password()` sur un rôle exempté posait `VALID UNTIL now()` : le rôle était bloqué alors que `v_role_status` l'affichait `exempt`, et rien ne relevait la borne avant un changement de mot de passe. Refusé désormais (`22023`, « role "…" is exempt from the policy », HINT : le retirer de `exempt_roles`), sans écriture ni audit. Test : `90_privileges` (`expire_exempt`) ; les tests de relèvement d'une borne posée par l'extension simulent un `expire_password()` antérieur à l'exemption (`ppp_test.expired_before_exemption()`). (3) `rotate_password()` / `switch_rotation_pair()` ne renvoient pas `valid_until` : signatures inchangées (compatibilité des clients), la valeur se lit dans `v_role_status.valid_until`. (A) **Sécurité** — `failed_attempts()`, accordée à `pass_policy_viewer`, renvoyait les noms inexistants tels que saisis par le client, un mot de passe tapé dans le champ utilisateur compris. Ces entrées (`role_missing`) ne sont plus nommées que pour un superutilisateur (le log serveur, qu'il lit déjà, contient ces noms) ; pour les autres appelants, elles sont agrégées en une seule ligne de `role_name` NULL (somme de `failed_count`, premier `first_failure_at`, dernier `last_failure_at`, `locked_until` le plus tardif). NULL plutôt qu'un libellé comme `<unknown roles>` : un rôle de ce nom pourrait exister et recevoir ces compteurs dans `v_role_status`. Limite : un rôle créé après des échecs sous son nom garde le drapeau jusqu'au prochain échec ou succès, et ses compteurs n'apparaissent alors qu'agrégés pour un non-superutilisateur. Test : `lockout.sh` (noms `regress_ghost_*` visibles du superutilisateur, absents pour un membre de `pass_policy_viewer`, une ligne agrégée, aucune jointure dans `v_role_status`). (B) **Sécurité** — pendant la fenêtre de démarrage (`locks_loaded` faux), les méthodes sans secret (`trust`, `peer`, `cert`, `gss`, `sspi`) laissaient entrer un rôle verrouillé dans `role_state`. Le hook refuse désormais tout rôle non exempté en `57P03` quelle que soit la méthode, superutilisateur compris sauf worker absent (règle inchangée) ; l'ancien constat accepté de §12 est retiré. Conséquence : l'accès local d'administration (`peer`, `trust`) attend lui aussi la fin de la fenêtre, sauf rôle listé dans `exempt_roles` (recommandé : `'postgres'`, README). Le superutilisateur des tests shell (`trust`) est exempté dans `common.sh`. §6.3 et README mis à jour. Test : `lockout.sh` (ligne `pg_hba.conf` `trust` pour un rôle verrouillé, fenêtre tenue ouverte → `57P03`, puis « locked » une fois les verrous réinjectés). (C) `lock_role()` sur un rôle exempté posait un verrou que le hook ignore, affiché `locked` et appliqué par surprise dès la sortie de la liste : refusé (`22023`, « role "…" is exempt from the policy: remove it from pg_pass_policy.exempt_roles first »). Test : `90_privileges` (`lock_exempt`). (D) `manage_valid_until = off` (ou rôle exempté) : `_rotate_role()` ne relève qu'une borne passée (`unblock`) ; après deux `switch_rotation_pair()` rapprochés, le rôle redevenu actif gardait la borne future posée par la première bascule et aurait été bloqué à la fin de `grace_period`. Nouveau mode `release` de `_apply_valid_until()` (borne écrite par l'extension, `rolvaliduntil = valid_until_synced`, levée même future ; valeur posée à la main conservée), appelé par `switch_rotation_pair()` pour le nouveau rôle actif quand l'extension ne gère pas son `VALID UNTIL`. Test : `55_pair` (`manage_valid_until = off`, trois bascules : l'actif n'a plus de borne, l'ancien reste borné). (E) `generate_password()` ignorait le rôle cible : la rotation d'un rôle au nom court échouait au hasard sur `PPP-017`. Le générateur est factorisé (`ppp_generate()`) ; nouvelle fonction C interne `_generate_password_for(role name, length int, profile text)` qui retire les tirages contenant le nom du rôle ou son inverse (toute casse, `reject_username`, noms de 3 caractères et plus), utilisée par `_rotate_role()`. Test : `40_generate` (1000 tirages de 512 caractères pour le rôle `abc` : aucun ne contient `abc`/`cba`, alors que des tirages de `generate_password()` en contiennent ; 200 contrôlés par `check_password()` ; 20 rotations de `abc` acceptées). (F) `check_password()` et `generate_password()` hors de `pg_pass_policy.database` : `check_password()` lève `PPP-003` dans tous les cas, `generate_password()` lève `PPP-003` avec `enforce_database = on`, sinon WARNING « password policy not applied outside database » et mot de passe produit (`ppp_require_policy_database()`, `policy.c`). Le contrôle de la base précède celui de l'extension. Test : `notify.sh` (base `ppp_otherdb`, `enforce_database` on puis off ; base `ppp_noext` : `PPP-003`). (G) `check_password()` différait du hook pour un vérificateur pré-haché (pas de `min_age`) et ignorait `superuser_bypass` : fonction d'évaluation partagée `ppp_evaluate_password()` (§6.2). Test : `20_complexity` (vérificateur SCRAM pré-haché, rôle lui-même dans l'intervalle `min_age` : `PPP-030` pour les deux ; `superuser_bypass = on` : mot de passe faible accepté par les deux). (H) Prédicat `may_check_history` écrit deux fois : helper `ppp_may_check_history()`. (I) `unlock_role()` lisait tout le hash (`failed_attempts()`) pour savoir si la shmem portait un verrou : nouvelle fonction C interne `_shmem_is_locked(role text)` (`HASH_FIND` sous verrou partagé, superutilisateur), tests `60_lock_unlock` inchangés.
- (vérification 7) Huit constats. (1) **Disponibilité** — la fenêtre de démarrage pouvait rester fermée indéfiniment worker présent (extension non fiable, verrous trop nombreux pour `max_tracked_roles`, `role_state` illisible) : l'exception superutilisateur ne joue que worker absent, et même un superutilisateur en `peer` ou en `trust` local recevait le `57P03` ; hors `exempt_roles`, l'instance n'était plus administrable. Décision : pendant la fenêtre, un superutilisateur authentifié avec succès par une méthode locale sans secret (`peer`, ou `trust` sur socket Unix : `port->raddr.addr.ss_family == AF_UNIX`, `ppp_auth_is_local_secretless()`, `lockout.c`) passe toujours, seule voie d'administration de secours ; il reste refusé « locked » si un verrou est en shmem ; un contrôle `peer` en échec garde le `57P03` (pas d'oracle) ; `trust` en TCP n'en bénéficie pas ; chaque admission est journalisée (LOG). L'encadré CAUTION du README, §6.3 (étape 8, « Démarrage ») et §12 sont mis à jour. Test : `lockout.sh` (fenêtre tenue ouverte, socket Unix ouverte et `pg_ident.conf` : superutilisateur non exempté accepté en `trust` local et en `peer`, refusé « locked » après `shmem_lock_role()` puis de nouveau accepté ; `peer` sans correspondance, `trust` TCP, rôle ordinaire en `trust` local : `57P03` ; LOG d'admission). (2) `failed_attempts()` se fiait au drapeau `role_missing` de l'entrée, rafraîchi seulement par une tentative : un rôle créé ou renommé sous un nom déjà tenté restait agrégé pour un non-superutilisateur, et un rôle renommé gardait son ancien nom visible (limite notée en vérification 6, (A)). L'existence est désormais décidée à la lecture, sur la copie et hors LWLock, par `SearchSysCacheExists1(AUTHNAME)`. Test : `lockout.sh` (nom inexistant verrouillé : non nommé pour le viewer ; `CREATE ROLE` : nommé ; `RENAME` : plus nommé ; nouveau `CREATE ROLE` : nommé). (3) La règle `release` n'était appliquée que par `switch_rotation_pair()` : `rotate_password()` d'un rôle non géré (`manage_valid_until = off` ou rôle exempté) laissait une borne future posée par l'extension, qui aurait bloqué le rôle à son échéance malgré le nouveau mot de passe. `_rotate_role()` appelle `_apply_valid_until()` en mode `release` (au lieu d'`unblock`) pour tout rôle dont le mot de passe vient d'être changé quand l'extension ne gère pas son `VALID UNTIL` ; l'appel supplémentaire de `switch_rotation_pair()` est supprimé ; les branches `unblock` et `release` de `_apply_valid_until()` sont fusionnées (`p_mode IN ('unblock', 'release')`, condition `rolvaliduntil > now()` pour `unblock` seulement). L'étape d de `run_maintenance()` garde `unblock` (mot de passe changé par un `ALTER ROLE` direct : seule une borne passée est relevée). Tests : `55_pair` (`manage_valid_until = off` : `rotate_password()` de l'ancien rôle de la paire, borne de paire conservée ; rôle hors paire, borne future écrite par l'extension levée, borne future posée à la main conservée), `90_privileges` (même chose pour un rôle exempté). (4) `check_password()` appliquait `superuser_bypass` (vérification 6, (G)) : un superutilisateur (client, CLI) qui vérifiait un mot de passe pour autrui le voyait conforme. Retour au comportement « répond pour le profil du rôle » : nouveau paramètre `bypass_complexity` de `ppp_evaluate_password()`, passé par le hook seulement ; §4, §5, §6.2 et README mis à jour. Test : `20_complexity` (`superuser_bypass = on` : `PPP-010` pour `check_password()`, `ok` pour le hook). (5) `generate_password()` hors de `pg_pass_policy.database` (`enforce_database = off`) répétait son WARNING à chaque appel : `ppp_require_policy_database()` réutilise le drapeau « une fois par session » du hook (`ppp_missing_schema_warned`). Test : `notify.sh` (trois `generate_password()` puis un `ALTER ROLE` dans une session : un seul WARNING). (6) `shmem_unlock_role()` et `_shmem_is_locked()` testaient `ppp_role_hash == NULL` après `ppp_check_shmem()`, qui lève déjà une ERROR dans ce cas : branches mortes supprimées. (7) `expire_password()` et `lock_role()` levaient deux messages différents pour un rôle exempté : helper `_require_not_exempt(name)` (`22023`, « role "…" is exempt from the policy », HINT « Remove it from pg_pass_policy.exempt_roles first. »), aucun droit accordé. Test : `90_privileges` (message et HINT identiques pour les deux fonctions). (8) Cette entrée.
- (vérification 8) Sept constats. (1) **Sécurité** — la voie de secours de la vérification 7 admettait pendant la fenêtre un superutilisateur verrouillé dans `role_state` (verrou persistant pas encore en shmem), par `peer` ou par `trust` sur socket Unix. Le hook ne peut pas lire `role_state` (pas de SPI dans `ClientAuthentication_hook`) et le worker ne l'a pas encore chargé : la condition « pas de verrou persistant » est invérifiable. Décision : voie restreinte à `peer` (`trust` exclu, même sur socket Unix : `ppp_auth_is_local_secretless()` devient `ppp_auth_is_peer()`) et aux superutilisateurs listés dans un nouveau GUC `pg_pass_policy.rescue_roles` (`PGC_SIGHUP`, défaut vide, même check hook que `exempt_roles`, `ppp_role_is_rescue()`) ; vide = aucun accès de secours, la voie d'administration reste `exempt_roles`. Le risque résiduel (rôle listé verrouillé dans `role_state`) est accepté en §12. Encadré CAUTION du README, §5, §6.3 (étape 8, « Démarrage ») et §12 mis à jour. Test : `lockout.sh` (liste vide : superutilisateur en `peer` `57P03` ; liste renseignée par `ALTER SYSTEM` + rechargement pendant la fenêtre : superutilisateur listé accepté en `peer` ; listé en `trust` local, non listé en `peer`, rôle ordinaire listé en `peer`, listé dont le contrôle `peer` échoue : `57P03`). (2) Le LOG d'admission de secours était écrit à chaque connexion : limité à une ligne par minute pour toute l'instance (`ppp_log_due(&ppp_shared->rescue_logged_at, …)`, `PPP_RESCUE_LOG_SECS`), avec un DETAIL qui rappelle `rescue_roles` et le verrou de `role_state` inconnu. Test : `lockout.sh` (trois admissions, un seul LOG). (3) `generate_password()` partageait le drapeau « une fois par session » du hook (vérification 7, (5)) : un `generate_password()` appelé d'abord faisait taire le WARNING d'un `ALTER ROLE … PASSWORD` non contrôlé, plus important. Un drapeau par source (`ppp_hook_not_applied_warned`, `ppp_generate_not_applied_warned`), message factorisé dans `ppp_warn_policy_not_applied()` (`policy.c`). Test : `notify.sh` (trois `generate_password()` puis deux `ALTER ROLE` : deux WARNING). (4) `check_password()` sautait `min_age` pour un superutilisateur appelant : la réponse doit être celle du profil du rôle (comme pour `superuser_bypass`, vérification 7 (4)) ; `ppp_check_secret()` passe désormais « appelant non superutilisateur » à `ppp_evaluate_password()`, le hook garde l'exception. §4 et README mis à jour. Tests : `30_history` (`min_age_superuser_check` : `PPP-030` ; `fresh_check` : `PPP-030`, la réutilisation reste montrée par le hook juste avant), `55_pair` et `70_maintenance` (`check_password()` répond `PPP-030`, la réutilisation `PPP-031` est vérifiée par un `ALTER ROLE` du superutilisateur, `reuse_hook`). (5) `role_missing` n'était rafraîchi que par une tentative d'authentification, alors que `failed_attempts()` décide par le syscache : l'éviction et la purge pouvaient traiter en fantôme un rôle créé depuis (ou l'inverse). `ppp_sync_cleanup()` (`worker.c`) rafraîchit le drapeau de chaque entrée à chaque synchronisation : noms copiés sous verrou partagé, `SearchSysCacheExists1(AUTHNAME)` hors LWLock, écriture sous verrou exclusif seulement si l'entrée a la même incarnation (`generation`). `failed_attempts()` ne fait sa recherche syscache que pour un appelant non superutilisateur (le drapeau ne sert qu'au regroupement). §4 et §6.3 mis à jour ; tests `lockout.sh` existants (visibilité par le viewer après `CREATE ROLE` / `RENAME`) inchangés. (6) Commentaires SQL : l'en-tête de `_apply_valid_until()` attribuait `unblock` à la rotation et l'étape d de `run_maintenance()` disait « comme rotate_password() » pour `unblock` : `release` est utilisé par la rotation (`_rotate_role()`), `unblock` par l'étape d seulement. (7) Cette entrée.
- (vérification 9) Revue de `6dc53b0..4158a82` (`src/`, `sql/`), neuf constats. (1-3, 5, 6) **Rafraîchissement de `role_missing` par le worker** (vérification 8, (5)) : `ppp_sync_cleanup()` recopiait l'existence courante dans le drapeau de toute entrée, dans les deux sens. (a) Une entrée d'un rôle supprimé ou renommé dont l'audit était en attente (`lock_pending_audit`, `pending_failures`) devenait fantôme, donc évinçable avant que le worker écrive ses lignes `role_gone` / `role_renamed` : audit perdu sous pression (reproduit sur un standby, où l'audit attend la promotion). (b) Un fantôme repassait à faux dès qu'un rôle était créé sous ce nom, et son pseudo-verrou était dès lors traité comme celui du nouveau rôle. (c) Chaque fantôme coûtait une recherche syscache négative à chaque tour. (d) La deuxième passe écrivait toutes les lignes sous verrou exclusif. Décision : le worker ne fait plus que la transition faux → vrai, pour les seules entrées sans rien en attente (`ppp_entry_may_become_ghost()`, `worker.c` : drapeau faux, ni `lock_pending_audit`, ni `pending_failures`, `audit_acked_seq = audit_lock_seq`, ni `lock_inflight`, ni verrou actif) ; seules ces entrées sont copiées et cherchées dans le syscache ; ne sont réécrites, sous le verrou exclusif déjà pris pour la purge, que les lignes dont le rôle est introuvable, pour la même incarnation (`generation`) et si l'entrée remplit encore les conditions. Le passage vrai → faux reste au hook d'authentification (succès, ou échec dont la recherche trouve le rôle : `lockout.c`, étape 4 de §6.3), comme avant la vérification 8. Une entrée devenue fantôme met fin à une série d'évictions infructueuses (`evict_fruitless_active`, comme une purge). §6.3 (worker) mis à jour. Tests : `standby.sh` (verrou local en attente d'audit, rôle supprimé sur le primaire : entrée non évincée par 24 noms inexistants, `role_locked` avec `role_missing` écrit après la promotion ; les deux assertions échouent avec le code de la vérification 8), `hashfull.sh` (16 compteurs vivants de rôles supprimés : l'échec d'un autre rôle n'est pas compté avant le tour du worker, il l'est après). (4) Le LOG d'admission de secours limité à une ligne par minute pour toute l'instance masquait des admissions ; la voie n'est ouverte qu'aux superutilisateurs de `rescue_roles` authentifiés en `peer` : chaque admission est journalisée, avec le nom du rôle ; `ppp_shared->rescue_logged_at` et `PPP_RESCUE_LOG_SECS` sont supprimés. README, §6.3 et §12 mis à jour. Test : `lockout.sh` (trois admissions, trois LOG). (7) **Parité `check_password()` ↔ hook** : la vérification 8, (4) faisait contrôler `min_age` par `check_password()` même pour un superutilisateur appelant (« réponse pour le profil du rôle », par analogie avec `superuser_bypass`), alors que le hook laisse passer l'`ALTER ROLE` d'un superutilisateur et que `ppp_evaluate_password()` doit répondre ce que le hook répondrait : un superutilisateur se voyait refuser par la fonction un changement que sa commande aurait accepté. Rétabli : `ppp_check_secret()` passe le vrai `caller_is_super` ; la réponse est celle de l'`ALTER ROLE … PASSWORD` du même appelant, dans les deux sens ; seule exception, `superuser_bypass` (complexité, vérification 7, (4)). Docstrings (`ppp_check_password()`, `ppp_evaluate_password()`, `ppp_check_secret()`), §4, §6.2, README (`check_password`, `PPP-030`) mis à jour. Tests : `30_history`, `55_pair` et `70_maintenance` reviennent aux réponses d'avant la vérification 8 (`min_age_superuser_check` vide, `fresh_check` et `reuse` : `PPP-031`, les `reuse_hook` sont gardés) ; nouveau `95_parity` qui fige la parité pour un superutilisateur et pour le rôle lui-même (`ok | ok`, `PPP-030`, `PPP-031`, `PPP-010` des deux côtés). (8) `trust` exclu et `rescue_roles` vide par défaut : un administrateur refusé ne savait pas où chercher. Le `FATAL` `57P03` porte un HINT générique, « If the condition persists, an administrator can connect through peer authentication as a superuser listed in pg_pass_policy.rescue_roles. », le même pour tout client : il ne dépend ni du rôle, ni de ses attributs, ni du contenu de la liste, et ne mentionne ni le worker ni `exempt_roles`. Encadré CAUTION du README, §6.3 (« Démarrage ») mis à jour. Test : `lockout.sh` (HINT présent pour un rôle ordinaire, identique pour un superutilisateur ; la sortie client ne mentionne toujours ni le worker ni `exempt_roles`). (9) `failed_attempts()` garde sa propre recherche syscache, voulu : commentaire dans `lockout.c`, entrée en §12. (10) Cette entrée.
- (vérification 10) Revue de `1303edd..9420658` (`src/`, `sql/`, `test/`), dix constats. (1) `ppp_entry_may_become_ghost()` refusait toute entrée verrouillée : le verrou permanent (`DT_NOEND`) d'un rôle supprimé gardait son entrée en `PPP_CLASS_KEEP` et son emplacement pour toujours (ou jusqu'à ce que la maintenance purge `role_state` et que le rechargement lève le verrou, s'il est recopié dans `role_state`). Un verrou actif n'empêche plus la transition s'il est entièrement audité et acquitté (ni `lock_pending_audit`, `audit_acked_seq = audit_lock_seq`, ni `lock_inflight`, ni `pending_failures`) ; il s'applique toujours au nom tant que l'entrée est là. Test : `hashfull.sh` (verrou permanent automatique audité et persisté, hash plein de compteurs vivants, `DROP ROLE`, l'échec d'un autre rôle évince l'entrée et est compté ; les deux assertions échouent sans la correction). En écrivant ce test, un défaut du parcours borné du mode COUNT (revue finale 4, H3) est apparu : quand `limit = nentries` (hash de moins de `PPP_EVICT_SCAN_LIMIT` entrées) et que le bucket de départ suit des buckets vides, le parcours s'arrête après la dernière entrée avant eux (`next_bucket < evict_fruitless_from`), le suivant repart de là et s'arrête au même endroit : la série infructueuse ne se terminait jamais, ni LOG « cannot track », ni pause d'une seconde (le test « LOG cannot track » de `hashfull.sh` échouait selon la position de départ laissée par les tests précédents). Un parcours qui a examiné toutes les entrées compte désormais comme un tour complet (`examined >= nentries`, `lockout.c`). (2-3) Le HINT du `57P03` informait un client non authentifié de la voie de secours, contre la règle écrite au-dessus (« rien n'est dit au client »). HINT client retiré, refus générique ; l'information complète (`exempt_roles`, `rescue_roles` en `peer`, superutilisateurs une fois le worker absent `PPP_WORKER_MISSING_GRACE_SECS` après l'initialisation) est dans le HINT du LOG serveur « refusing connections … ». README (encadré CAUTION, « Verrouillage et déverrouillage »), §6.3, §12 mis à jour. Test : `lockout.sh` (aucun HINT pour un rôle ordinaire ni pour un superutilisateur ; la sortie client ne cite ni worker, ni `exempt_roles`, ni `rescue_roles`, ni `peer` ; le HINT du LOG serveur cite les trois voies). (4) Le LOG de secours n'était pas borné : limitation par rôle, tableau fixe `ppp_shared->rescue_log` de `PPP_RESCUE_LOG_SLOTS` (16) cases sous le verrou du hook, une ligne par rôle et par `PPP_RESCUE_LOG_SECS` (60 s), la suivante donne le nombre d'admissions non journalisées du rôle ; tableau plein, journalisation sans limite. Test : `lockout.sh` (trois admissions d'un rôle, un LOG ; un second rôle a le sien dans la même minute ; une minute plus tard, nouveau LOG avec « 2 earlier admissions of this role were not logged » ; échoue sans la correction). (5) Course entre la recherche syscache de `ppp_sync_cleanup()` hors verrou et l'écriture : un rôle créé et authentifié entre-temps était marqué fantôme (le hook laisse le drapeau à faux, la génération ne change pas). Compteur par entrée `update_seq`, incrémenté par le hook à chaque mise à jour (succès comme échec compté) et partout où le drapeau est remis à faux (`ppp_apply_lock_ops()`, rechargement), copié par le worker et exigé égal à l'écriture. Course non reproductible de façon déterministe dans les tests shell (aucun point d'injection entre la copie et l'écriture) : pas de test dédié. (6) La transition vrai → faux supprimée par le worker est voulue : entrée en §12. (7) `check_password()` appelée par un superutilisateur ignore `min_age` alors que le rôle cible, changeant lui-même son mot de passe, sera refusé : accepté, la fonction répond pour l'appelant (parité avec le hook, vérification 9) ; README (paragraphe `check_password`) et §12. (8) `ppp_sync_cleanup()` allouait une ligne par entrée du hash : les candidates sont d'abord comptées sous verrou partagé, puis copiées dans autant de lignes (plus `PPP_HASH_COPY_MARGIN`) ; la seconde compaction est remplacée par une marque `gone` par ligne. (9) `95_parity` laissait ses lignes `par1` à `par4` dans `ppp_test.secrets` : vérifiées par `ppp_test.leaks()` puis supprimées à la fin du test. (10) `hashfull.sh` : le `sleep 1` après le tour du worker est remplacé par une attente bornée par sondage (`wait_until`, ajouté à `common.sh` : relance une commande jusqu'à ce qu'elle réussisse, au plus N secondes).
- (vérification 11) Revue de `9420658..ebccd9d` ; **annule la décision (1) de la vérification 10**. Laisser un verrou audité devenir fantôme introduisait trois défauts : (1) le verrou d'un rôle supprimé était évincé par des noms inventés et disparaissait avec un simple DEBUG1 ; (2) un rôle recréé sous le même nom héritait ou non de l'ancien verrou selon la pression sur le hash ; (3) chaque rechargement réinjectait en `PPP_ENTER_PRIORITY` le verrou orphelin d'une ligne `role_state` (`COALESCE(rolname, role_name)`), qui redevenait fantôme et évinçait un compteur réel. Décision : une entrée verrouillée ne devient **jamais** fantôme (`ppp_entry_may_become_ghost()` refuse de nouveau tout verrou actif ; `ppp_ack_pending()` ne fait plus d'un verrou audité `role_missing` un fantôme ; le hook ne remet plus à jour `role_missing` sur une entrée qu'il refuse « locked »). Le verrou est rattaché à l'OID de son rôle : champ `lock_role_oid` (distinct d'`audit_role_oid`, qui reste l'OID du verrou automatique en attente d'audit), posé par le hook au verrou automatique, par `ppp_apply_lock_ops()` (`get_role_oid()` avant le LWLock) et par la réinjection. Au nettoyage, une entrée verrouillée dont le verrou est entièrement audité et acquitté et dont aucun rôle de cet OID ne porte plus le nom (`SearchSysCache1(AUTHOID)` : supprimé ou renommé) est retirée du hash (`HASH_REMOVE` sous verrou exclusif, mêmes contrôles de `generation`, d'`update_seq` et de `lock_role_oid`), avec un LOG « lock of dropped role "…" released ». Le rechargement joint `pg_roles` par OID et ignore les lignes de `role_state` dont le rôle n'existe plus ; `run_maintenance()` continue de les purger. Test : `hashfull.sh` (verrou permanent audité, hash plein, `DROP ROLE` → l'entrée a disparu au tour suivant du worker et le LOG est présent, la place libérée compte l'échec d'un autre rôle ; `CREATE ROLE` du même nom → connexion réussie, avant et après un rechargement, aucun verrou en shmem ; avec le code de `ebccd9d`, les assertions « entrée disparue » et « LOG » échouent). (4) Le compteur des admissions de secours non journalisées n'était écrit qu'à une admission suivante du même rôle : `ppp_flush_rescue_log()`, appelée en tête de chaque synchronisation du worker (relances de la fenêtre comprises), journalise les compteurs dont la période est écoulée et tous ceux qui restent dès que `locks_loaded` est vrai, puis vide la case (`logged_at` gardé). Test : `lockout.sh` (après la minute, LOG du worker « 2 admissions … were not logged » sans nouvelle admission ; une admission dans la période suivante est journalisée par le worker à la fermeture de la fenêtre, « 1 admission … was not logged »). (5) Horloge qui recule : une différence négative compte comme période écoulée (`ppp_rescue_period_elapsed()`). (6) `errdetail_plural` pour « N earlier admission(s) », période tirée de `PPP_RESCUE_LOG_SECS` dans les textes ; les deux `ereport` du hook n'en font plus qu'un. (7-8) `ppp_sync_cleanup()` revient à une seule passe sous verrou partagé (`ppp_alloc_hash_copy()`, sur-allocation bornée à une ligne par entrée plus `PPP_HASH_COPY_MARGIN`) et à la compaction en place des lignes changées ; le drapeau `gone` est supprimé. (9) L'attente réelle de 61 s de `lockout.sh` est acceptée (pas de GUC de test) : raison consignée dans `docs/TESTING.md` ; une assertion avant et une après l'attente vérifient que la fenêtre est toujours ouverte (`worker_status().locks_loaded = false`), pour qu'un échec soit explicite plutôt qu'intermittent.
- (vérification 12) Revue de `c4c09b9..1c96b67`, sept constats. (1) Le rechargement joignait `role_state` à `pg_roles` par OID seulement : après une restauration, avant que `run_maintenance()` ne remappe les OID (étape a0), un verrou persisté était perdu et la fenêtre de démarrage se fermait quand même. Décision : réinjection par OID si le rôle existe, sinon par nom si un rôle de ce nom existe (comportement d'avant la vérification 11), ligne ignorée seulement si ni l'OID ni le nom n'existent ; `lock_role_oid` reçoit l'OID du rôle trouvé. (2) `ppp_role_gone()` traitait un rôle renommé comme supprimé et libérait son verrou (sur un standby, un verrou local posé par `shmem_lock_role()` disparaissait ainsi). « Supprimé » signifie désormais que l'OID n'existe plus ; le verrou audité et acquitté d'un rôle renommé est déplacé sous le nouveau nom (`HASH_REMOVE` puis `ppp_enter_role()` sous le verrou exclusif, mêmes contrôles de `generation`, d'`update_seq` et de `lock_role_oid`, fusion en gardant le verrou le plus long si une entrée existe sous le nouveau nom, verrou laissé sous l'ancien nom si cette entrée a quelque chose en attente), LOG « lock of role "…" follows its rename to "…" ». (3) `shmem_lock_role()` sur un nom sans rôle posait un verrou d'OID inconnu, jamais libéré : ERROR `42704` « role "…" does not exist » (`get_role_oid(…, false)`) au moment de l'appel ; `lock_role()` vérifie déjà le rôle. (4) Le hook remettait `role_missing` à faux sur un succès refusé « locked » : le pseudo-verrou d'un nom inventé devenait le verrou permanent d'un rôle créé ensuite sous ce nom ; `role_missing` n'est plus touché quand la connexion est refusée pour verrou, succès comme échec. (5) `ppp_flush_rescue_log()` est appelée aussi après `ppp_sync_reload()` : la fermeture de la fenêtre dans le même tour vide les compteurs. (6) Coût d'une recherche `AUTHOID` par verrou et par tour : accepté (§12). (7) L'assertion de `hashfull.sh` sur le rechargement ne prouvait rien (la maintenance avait déjà purgé la ligne) : commentaire corrigé, et nouveau scénario sans maintenance (`worker_interval = 0`, redémarrage). Tests : `60_lock_unlock` (`shmem_lock_role()` d'un nom inexistant → `42704`, aucune entrée), `hashfull.sh` (pseudo-verrou d'un nom inventé, `CREATE ROLE` de ce nom, connexion refusée puis entrée évincée par des noms inventés ; lignes `role_state` écrites à la main, orphelin réel ignoré et fenêtre fermée, OID périmé portant le nom d'un rôle existant réinjecté par le nom, puis renommage : LOG « follows its rename »), `standby.sh` (verrou local d'un rôle renommé sur le primaire : il suit le nouveau nom, le rôle recréé sous l'ancien nom se connecte), `lockout.sh` (verrou automatique audité sous l'ancien nom après un renommage : il suit désormais le nouveau nom, LOG compris, au lieu de « le nouveau nom repart de zéro ») ; avec le code de `1c96b67`, les assertions de (1), (2), (3) et (4) échouent.
- (vérification 13) Revue de `1c96b67..7ab9ae9` ; **remplace la décision (2) de la vérification 12**. Le déplacement du verrou au renommage introduisait cinq défauts : la fusion forçait `role_missing` à faux, si bien que le pseudo-verrou sans OID d'un nom inventé passait au rôle réel créé sous ce nom et n'était jamais libéré ; la fusion « verrou le plus long » gardait l'OID d'un rôle supprimé et faisait perdre le verrou déplacé ; l'entrée créée recevait les paramètres du profil par défaut ; `ppp_enter_role()` pouvait renvoyer NULL après le retrait ; le verrou automatique déplacé n'était pas dans `role_state` et se perdait au redémarrage. Décisions : (A) le déplacement est supprimé (code de fusion, LOG « follows its rename »). (B) Contrôle structurel dans le hook (étape 5 de §6.3) : un verrou ne s'applique à la connexion que si `lock_role_oid` est égal à l'OID du rôle qui se connecte, ou si `lock_role_oid` est invalide et que le nom n'a pas de rôle (pseudo-verrou) ; la recherche `ppp_role_lookup()` est désormais faite à chaque connexion (elle ne l'était qu'à un échec compté ou pendant la fenêtre de démarrage) et, sautée, le verrou s'applique. Le verrou d'un autre rôle ne s'applique pas : entrée sans rien en attente (`ppp_entry_settled()`, déplacée dans `pg_pass_policy.h`) → remise à zéro pour le nouveau rôle sous le verrou exclusif (`ppp_restart_entry()`, paramètres du profil gardés) et chemin normal (échec compté, succès) ; entrée avec un audit en attente de l'autre rôle → laissée telle quelle et connexion admise sans rien compter. Ce dernier choix est le plus simple et sûr : l'audit en attente appartient à l'autre rôle et ne doit être ni perdu ni mêlé aux échecs du nouveau, et la fenêtre se referme au tour suivant du worker, qui audite l'entrée (puis la retire, ou la connexion suivante la remet à zéro) (sur un standby, elle dure jusqu'à la promotion ou à l'éviction de l'entrée : limite §12). (C) Nettoyage : une entrée verrouillée, verrou audité et acquitté, dont `lock_role_oid` existe sous un autre nom est retirée du hash avec un LOG « lock of role "…" renamed to "…": reloaded from role_state », et `ppp_reload_pending` est levé : le rechargement du même tour réinjecte par OID, sous le nouveau nom, le verrou persisté. Vérifié : le verrou automatique audité est bien persisté dans `role_state` (upsert de `ppp_sync_pending()`, `locked_by = 'auto'`, par OID) sauf si le rôle a disparu ou a été renommé avant son audit ; ce dernier cas et le verrou local d'un standby (`shmem_lock_role()`) ne suivent pas le renommage : limite documentée (§12, README) plutôt qu'un nouveau mécanisme. OID disparu : inchangé (retrait, LOG « dropped »). (D) Rechargement : le repli par nom ne s'applique que si `role_state` n'a aucune ligne pour l'OID actuel du rôle trouvé par nom (`NOT EXISTS`) : une ligne périmée ne l'emporte plus sur la ligne réelle. (E) `ppp_apply_lock_ops()` : `get_role_oid(…, false)` au PRE_COMMIT, ERROR `42704` si le nom n'a plus de rôle (renommé ou supprimé dans la même transaction). (F) `standby.sh` : le `sleep 3` du scénario de renommage est remplacé par une attente bornée par sondage du LOG (`wait_until`). Tests : `60_lock_unlock` (`shmem_lock_role()` puis `ALTER ROLE … RENAME` dans la même transaction → `42704` au COMMIT, aucune entrée), `hashfull.sh` (pseudo-verrou d'un nom inventé puis `CREATE ROLE` : connexion réussie ; ligne périmée d'un rôle qui a sa propre ligne non verrouillée : pas de repli par le nom ; rôle réinjecté par le nom puis renommé : LOG « renamed to », rien à réinjecter), `lockout.sh` (verrou automatique audité et persisté, renommage puis recréation de l'ancien nom : LOG, le nouveau nom reste verrouillé après le tour du worker, l'ancien nom recréé se connecte ; verrou non persisté d'un rôle renommé avant l'audit : le nouveau nom repart de zéro ; `DROP ROLE` + `CREATE ROLE` du même nom, verrou en mémoire partagée seulement : le nouveau rôle se connecte avant le tour du worker ; verrou réglé d'un autre OID rencontré par le hook avant le worker : entrée remise à zéro, échec compté ; l'attente de 6 s de l'expiration est supprimée, l'entrée étant retirée une fois le verrou audité), `standby.sh` (verrou local d'un rôle renommé : LOG, le rôle renommé repart de zéro, le rôle recréé n'hérite de rien). Avec le code de `7ab9ae9`, échouent : le pseudo-verrou (connexion refusée), le repli par nom (rôle verrouillé à tort), la connexion du rôle recréé avant le tour du worker, le COMMIT de `60_lock_unlock` (accepté) et les LOG « renamed to » ; le scénario du verrou persisté renommé ne diffère que par le LOG (le rechargement par OID suffisait déjà au nouveau nom).
- (vérification 14) Revue de `7ab9ae9..63a6575` : le contrôle par OID de la vérification 13 rendait le hook **permissif** dans plusieurs cas. Principe non négociable retenu : dans le doute, le verrou s'applique (fail-closed). (1) Verrou d'un autre rôle avec audit en attente : la connexion passait sans rien compter, d'où une force brute illimitée pendant la fenêtre (jusqu'à la promotion sur un standby) ; elle est désormais **refusée comme verrouillée**, quel que soit le statut, jusqu'à l'audit (limite §12 : disponibilité sacrifiée à la sûreté). (2) Un verrou à `lock_role_oid` invalide cédait dès que le nom avait un rôle ; il ne cède plus que s'il s'agit d'un pseudo-verrou certain (nouveau drapeau `lock_on_missing`, posé par le hook quand la recherche a été faite et que le nom n'avait pas de rôle ; effacé par `shmem_lock_role()` et la réinjection) et que le rôle existe maintenant ; tout autre verrou d'OID inconnu s'applique, comme un verrou quand la recherche est sautée ou échoue (`ppp_lock_is_foreign()`). (3) `ppp_restart_entry()` gardait les paramètres du profil de l'ancien rôle et ne demandait aucun rechargement : elle appelle maintenant `ppp_init_entry()` (valeurs par défaut) et lève `reload_requested` (le worker est réveillé après le relâchement du verrou, `ppp_signal_worker_reload()`) : le rechargement fixe le profil du nouveau rôle et réinjecte sous son nouveau nom le verrou persisté d'un rôle renommé. (4) Les compteurs d'un rôle supprimé étaient hérités par le rôle recréé sous le même nom (quatre échecs audités + un échec du nouveau rôle = verrou) : nouveau champ `owner_oid`, posé à chaque échec compté ; à un échec à compter ou à un succès, une entrée dont `owner_oid` est valide et différent de l'OID du rôle est remise à zéro (même chemin que (3)) si elle est réglée, sinon la connexion est refusée comme verrouillée (« temporarily locked »), bon mot de passe compris, jusqu'au tour du worker. (5) Renommage : le nettoyage retirait l'entrée de l'ancien nom même quand `role_state` n'avait pas le verrou, qui était alors perdu ; il ne la retire plus que si `role_state` a, pour l'OID, une ligne dont `locked_until` couvre le verrou (`ppp_lock_persisted()`, requête SPI sous un instantané récent) et que l'instance n'est pas un standby ; sinon l'entrée reste sous l'ancien nom, sans LOG (limite §12 : le verrou local d'un standby ne suit pas le renommage). (6) Repli par nom du rechargement conservé (sûreté après restauration) ; le cas `DROP ROLE` puis `CREATE ROLE` du même nom avant la maintenance, qui peut verrouiller le nouveau rôle, est documenté comme fail-closed (§12). (7) L'ERROR `42704` au PRE_COMMIT de la vérification 13 est retirée : `shmem_lock_role()` capture l'OID à l'appel (le rôle existe alors, sinon `42704` comme avant), passé à `ppp_defer_op()`, et le PRE_COMMIT l'utilise même si le rôle a été renommé ou supprimé dans la transaction ; le nettoyage du worker gère ensuite renommage et suppression. (8) La recherche `ppp_role_lookup()` n'est plus faite à chaque connexion : `HASH_FIND` d'abord sous verrou partagé, recherche seulement pour un échec à compter, pendant la fenêtre de démarrage, ou si l'entrée porte un verrou actif ou, pour que (4) ne soit pas un oracle, quelque chose en attente pour un OID connu (`ppp_lookup_needed()`) ; si l'entrée retrouvée sous le verrou exclusif en a besoin entre-temps, le verrou est relâché pour la recherche et repris. Tests (tous échouent avec `63a6575`, vérifié) : `lockout.sh` (`DROP ROLE` + `CREATE ROLE` avec verrou en attente d'audit → connexion du nouveau rôle refusée ; quatre échecs audités, `DROP ROLE` + `CREATE ROLE`, un échec → compteur à 1 sans verrou, puis connexion réussie ; mêmes échecs non audités → nouveau rôle refusé, accepté après le tour du worker ; verrou permanent non persisté d'un rôle renommé avant l'audit → entrée conservée sous l'ancien nom, aucun LOG de retrait ; scénario `regress_ren` : aucun LOG de retrait), `hashfull.sh` (pseudo-verrou d'un nom inventé, rôle créé avant l'audit → refusé, accepté après le tour du worker ; rôle réinjecté par le nom puis renommé, ligne `role_state` d'un OID périmé → aucun LOG de retrait), `standby.sh` (verrou local d'un rôle renommé : aucun LOG de retrait, verrou conservé sous l'ancien nom après deux tours du worker du standby ; le rôle recréé sous l'ancien nom se connecte), `60_lock_unlock` (`shmem_lock_role()` puis `ALTER ROLE … RENAME` dans la même transaction → COMMIT accepté, verrou sous l'ancien nom). Le cas d'un verrou d'OID inconnu qui n'est pas un pseudo-verrou (recherche sautée) n'est pas atteignable depuis un test : seul le pseudo-verrou en attente d'audit l'est (`hashfull.sh`).

## 12. Constats de revue acceptés

Depuis la séparation en trois dépôts, les constats acceptés de la CLI et du web
sont aussi consignés dans la rubrique « Limites connues » de leurs README
([CLI](https://github.com/gliatti/pg_pass_policy-cli#limites-connues),
[web](https://github.com/gliatti/pg_pass_policy-web#limites-connues)).
Les entrées ci-dessous, y compris les chemins `cli/…` et `web/…` qu'elles
citent, sont conservées telles qu'elles ont été écrites.

Points relevés en revue et volontairement non corrigés :

- **Oracle d'énumération sous saturation du hash** : en remplissant le hash
  de noms inexistants, un attaquant fait évincer le pseudo-verrou d'un nom
  inexistant alors que celui d'un vrai rôle reste (§6.3, « Noms
  inexistants ») ; rendre les pseudo-verrous non évincables rouvrirait
  l'occupation du hash par des noms fantômes, et l'attaque exige de l'ordre
  de `max_tracked_roles` tentatives, visibles dans l'audit agrégé.
- **`verifier_pending` avec `enforce_database = off`** : un changement fait
  hors du hook juste après un changement passé par le hook est pris pour
  l'écart de sel attendu (§11, H4) ; sans le mot de passe en clair, deux
  vérificateurs SCRAM de sels différents ne se comparent pas, et les défauts
  (`enforce_database = on`, `enabled = on`) limitent le cas aux rôles
  exemptés.
- **Renommage d'un rôle et verrou automatique** (vérification, constat 5) :
  la shmem tient compteurs et verrous automatiques par nom, `role_state` par
  OID. Après `ALTER ROLE … RENAME`, le nouveau nom repart de zéro (compteur
  vide). Un verrou automatique déjà recopié dans `role_state` suit le rôle
  au rechargement suivant (lu par OID) ; un verrou encore en attente
  d'audit reste attaché à l'ancien nom, qui ne se connecte plus : il est
  audité avec `role_missing` (et `role_renamed` / `renamed_to` si le nouveau
  nom est connu) sans être recopié dans `role_state` ; une fois audité et
  acquitté, l'entrée de l'ancien nom est conservée (vérification 14 : le
  worker ne la retire que si `role_state` a, pour l'OID, une ligne qui
  couvre le verrou, et jamais sur un standby) : le verrou n'est pas perdu,
  mais il ne s'applique pas au rôle sous son nouveau nom. De même, le
  verrou local posé sur un standby par `shmem_lock_role()` (absent de
  `role_state`) reste sous l'ancien nom et ne suit pas un renommage rejoué
  depuis le primaire (le renommage exige `CREATEROLE` sur le primaire, où
  `lock_role()` est disponible). Si un autre rôle prend ensuite l'ancien
  nom et se connecte, l'entrée réglée est remise à zéro pour lui (étape 5) :
  ce verrou non persisté disparaît alors. Entre le renommage et le tour
  suivant du worker, le nouveau nom n'a pas d'entrée : même un verrou
  persisté ne s'applique à lui qu'après le rechargement de ce tour.
  L'administrateur qui renomme un compte à bloquer durablement dispose de
  `lock_role()` (persisté, réinjecté par OID). Un **autre rôle créé sous
  l'ancien nom** (`DROP ROLE` puis `CREATE ROLE`, avant ou après le passage
  du worker) ne reçoit ni le verrou ni les compteurs de l'ancien : le hook
  n'applique un verrou qu'à l'OID qu'il désigne (vérification 13) et
  remet à zéro, avant de compter, l'entrée réglée dont les compteurs
  appartiennent à un autre OID (`owner_oid`, vérification 14) ; le worker
  compare l'OID, n'écrit rien dans `role_state` pour lui et audite
  `role_missing` / `role_recreated`. Une fois le verrou audité, le worker
  retire l'entrée du hash (OID disparu, vérification 11, ou porté par un
  autre nom avec un verrou persisté, vérifications 13 et 14), et le
  rechargement ignore la ligne `role_state` d'un OID disparu dont le nom
  n'existe plus : le nouveau rôle part d'une entrée propre.
- **Nouveau rôle bloqué tant que l'audit de l'ancien est en attente**
  (vérification 14) : tant que l'entrée garde un audit en attente d'un autre
  rôle (verrou automatique, échecs non écrits), la connexion du rôle qui
  porte maintenant le nom est refusée comme verrouillée, bon mot de passe
  compris (étapes 5 et 5 bis de §6.3) : un tour du worker sur un primaire,
  jusqu'à la promotion (ou l'éviction de l'entrée) sur un standby. La
  disponibilité est sacrifiée à la sûreté : admettre la connexion sans rien
  compter (vérification 13) ouvrait une force brute illimitée pendant cette
  fenêtre. De même, un verrou dont l'OID est inconnu s'applique à quiconque
  porte le nom, sauf pseudo-verrou certain d'un nom qui n'avait pas de rôle
  (`lock_on_missing`), et un verrou s'applique quand la recherche du rôle a
  été sautée.
  Limite restante : `run_maintenance()` rattache par nom au nouvel OID les
  lignes d'un OID disparu (cas d'une restauration, commentaire de l'étape
  a0) et le rechargement fait de même tant que la maintenance n'est pas
  passée (repli par nom, réservé à un rôle sans ligne `role_state` pour
  son propre OID, vérification 13) ; un `DROP ROLE` puis `CREATE ROLE` du
  même nom avant le passage de la maintenance est indiscernable d'une
  restauration et fait donc hériter le nouveau rôle d'un verrou déjà
  persisté, par l'étape a0 comme par le repli par nom. Le repli est
  conservé (vérification 14) : il garantit la sûreté après une
  restauration ; l'effet est fail-closed (un rôle verrouillé à tort, jamais
  un verrou perdu) et il exige une action privilégiée (`CREATEROLE`) ;
  `unlock_role()` lève le verrou hérité.
- **Perte bornée d'audit sur standby / éviction** : une entrée dont le
  verrou a expiré et dont l'audit est en attente peut être évincée (tout de
  suite sur un standby, après 24 h sur un primaire) avec un LOG (§6.3,
  « Perte bornée ») ; la garder interdirait le comptage des vrais rôles une
  fois le hash rempli par un worker qui ne peut pas écrire.
- **Deux appels Vault au préflight (CLI, pour mémoire)** : le préflight de
  `pgpp` interroge Vault deux fois ; le coût est négligeable pour une
  commande d'administration ponctuelle, et le point relève de `cli/`, hors du
  périmètre de l'extension.
- **Copies non effacées dans les tampons des bibliothèques**
  (sqlx/reqwest/PgRow côté CLI et web) : les mots de passe générés
  transitent par des tampons internes que nous ne pouvons pas effacer ; les
  effacer exigerait de réécrire ou de forker ces bibliothèques, pour un gain
  faible face à un attaquant qui lit déjà la mémoire du processus.
- **Fenêtre de démarrage fermée indéfiniment** (revue finale 6 ; le volet
  « méthodes sans secret » est corrigé en vérification 6, §11) : un worker
  qui ne démarre pas (base inexistante, `max_worker_processes` épuisé) ou
  des verrous trop nombreux pour `max_tracked_roles` laissent la fenêtre
  fermée indéfiniment pour les rôles non exemptés, quelle que soit la
  méthode d'authentification (superutilisateurs compris tant que le worker
  tourne, voir ci-dessous) : c'est le choix fail-closed, signalé par le LOG
  « worker_pid = 0 », les autres LOG et `worker_status().locks_loaded` faux.
  L'accès d'administration pendant la fenêtre passe par `exempt_roles` ou,
  pour un superutilisateur de `rescue_roles`, par `peer` (vérifications 7
  et 8, §6.3 « Démarrage »).
- **Superutilisateur de secours pendant la fenêtre** (vérification 7,
  restreint en vérification 8) : un superutilisateur listé dans
  `pg_pass_policy.rescue_roles` et verrouillé dans `role_state` (pas encore
  en shmem) entre pendant la fenêtre par `peer`. Le hook ne peut pas lire
  `role_state` et le worker ne l'a pas encore chargé : la condition « pas de
  verrou persistant » est invérifiable à ce moment. Accepté, dans ces seules
  limites : liste vide par défaut (aucun accès de secours), rôles listés
  explicitement par l'administrateur, `peer` seulement (le rôle est lié à un
  compte système du serveur, qui donne déjà les fichiers de données),
  `trust` exclu même sur socket Unix. Sans cette voie, une fenêtre maintenue
  fermée (extension non fiable, hash plein) ne laisse que `exempt_roles`
  pour administrer l'instance. Les admissions sont journalisées (LOG avec
  le nom du rôle, une ligne par rôle et par minute depuis la vérification
  10, la suivante donnant le nombre d'admissions non journalisées ; sans
  limite pour un rôle qui ne trouve pas de case libre).
- **Superutilisateurs quand le worker est absent** (revue finale 7, restreint
  en revue finale 8) : pendant un démarrage normal (worker présent), ils
  reçoivent le `57P03` comme les autres. Ils ne passent que lorsque le
  worker est démontrablement absent (`worker_pid = 0` plus de 10 s après
  l'initialisation de la shmem : base `pg_pass_policy.database` inexistante,
  `max_worker_processes` épuisé), pour qu'une installation neuve dont le
  worker ne démarre pas (`exempt_roles` vide par défaut) reste administrable
  par mot de passe. Conséquences acceptées, dans ce seul cas : un
  superutilisateur verrouillé dans `role_state` (et pas encore en shmem)
  peut se connecter, ce que `exempt_roles` permettait déjà pour les rôles
  exemptés ; un superutilisateur peut par ailleurs se donner tous les
  droits, le verrou ne le protège que d'un mot de passe compromis. Et la
  réponse distingue un nom de superutilisateur (vraie réponse) d'un autre
  nom (`57P03`) : oracle d'énumération limité aux superutilisateurs et à une
  installation dont le worker ne tourne pas, situation que le log signale
  (LOG « worker_pid = 0 » une fois par minute). Un worker qui redémarre
  après un FATAL laisse aussi `worker_pid = 0` pendant `bgw_restart_time`
  (10 s) : si la fenêtre est encore fermée à ce moment, l'exception
  s'applique pendant ce délai.
- **`failed_attempts()` garde sa propre recherche syscache** (vérification
  9) : la fonction décide de l'existence de chaque nom par
  `SearchSysCacheExists1(AUTHNAME)` au moment de l'appel (appelant non
  superutilisateur), au lieu du drapeau `role_missing` que le worker tient
  à jour. Voulu : la vue doit être exacte au moment de la lecture, le
  drapeau n'est qu'un cache pour les classes d'éviction (passé à vrai par
  le worker seulement pour les entrées sans rien en attente ni verrou
  actif, à faux par le hook seulement). Coût accepté : une recherche syscache par entrée et par
  appel, hors LWLock.
- **`_audit()` lève une erreur sans bibliothèque préchargée** : `_audit()`
  appelle la fonction C `_worker_pid()`, dont le chargement échoue quand la
  bibliothèque n'est pas dans `shared_preload_libraries` (`_PG_init()` le
  refuse) ; toute action auditée échoue alors avec sa transaction, ce qui est
  cohérent avec le choix fail-closed de §11 E6 : sans préchargement, ni le
  hook ni le verrouillage ne fonctionnent, et journaliser comme si de rien
  n'était masquerait la panne.
- **Recherche `AUTHOID` par verrou et par tour** (vérification 12) : chaque
  tour du nettoyage cherche dans le syscache l'OID de chaque entrée
  verrouillée dont le verrou est audité (permanents compris) pour détecter
  une suppression ou un renommage. Coût accepté : le nombre de verrous
  actifs est faible, la recherche est faite hors LWLock et le syscache la
  sert en mémoire. De même, le hook fait sa recherche `AUTHNAME` à un
  échec compté, pendant la fenêtre de démarrage, et pour une entrée qui
  porte un verrou actif ou quelque chose en attente pour un OID connu
  (vérification 14 : l'OID dit à qui appartient un verrou ou un compteur ;
  la vérification 13 la faisait à chaque connexion) : une recherche que
  PostgreSQL vient de faire pour l'authentification, servie par le
  syscache. Le nettoyage fait en outre une requête SPI sur `role_state` par
  entrée verrouillée d'un rôle renommé, à chaque tour tant que l'entrée
  reste sous l'ancien nom (vérification 14) : cas rare, coût accepté.
- **Refus `57P03` sans indication au client** (vérification 10) : le HINT
  ajouté en vérification 9, (8), qui rappelait la voie de secours
  (`rescue_roles` en `peer`), est retiré. La confidentialité vis-à-vis du
  client non authentifié l'emporte sur l'indication : le refus reste
  générique, et l'administrateur trouve l'information complète
  (`exempt_roles`, `rescue_roles` en `peer`, superutilisateurs une fois le
  worker absent) dans le HINT du LOG serveur et dans la documentation.
- **Tentatives antérieures à la création d'un rôle** (vérification 10) :
  le worker ne fait que la transition `role_missing` faux → vrai, jamais
  vrai → faux. Voulu : les tentatives faites sous un nom avant la création
  du rôle restent des tentatives fantômes (évincables, purgées selon la
  règle des noms inexistants) ; la première tentative du rôle réel
  (succès, ou échec dont la recherche trouve le rôle) remet le drapeau à
  faux. Un fantôme dont le nom est repris ne transmet pas ainsi son
  pseudo-verrou par le worker.
- **`check_password()` d'un superutilisateur et `min_age`** (vérification
  10) : appelée par un superutilisateur, la fonction ignore `min_age`
  (comme son `ALTER ROLE … PASSWORD`), alors que le rôle cible, en
  changeant lui-même son mot de passe, sera refusé (`PPP-030`). Accepté :
  la fonction répond pour l'appelant (parité avec le hook, choix de la
  vérification 9, (7)) ; un superutilisateur qui prépare un mot de passe
  pour le rôle lui-même doit tenir compte de `min_age` (README).

Revue de clôture : constats restants, volontairement non traités.

- **Audit des refus uniquement en LOG** : un `password_rejected` n'a pas de ligne `audit_log` ni de NOTIFY (l'ERROR annule la transaction, §6.2) ; une trace en table exigerait une file en mémoire partagée vidée par le worker (§11, agent core).
- **Oracle d'énumération sous saturation du hash** : maintenu, voir plus haut.
- **`verifier_pending` avec `enforce_database = off`** : maintenu, voir plus haut.
- **Perte bornée d'audit sur standby** : maintenue, voir plus haut.
- **Superutilisateurs pendant la fenêtre de démarrage** : ils ne passent que si le worker est absent, voir plus haut.
- **Renommage a → b → a et recréation sous le même nom** (vérification 4) : limites déjà listées, maintenues ; voir « Renommage d'un rôle et verrou automatique » plus haut (verrou en attente d'audit attaché au nom jusqu'à son audit ; depuis la vérification 11, l'entrée d'un rôle supprimé ou renommé est ensuite retirée du hash) et §11, vérification 2, constat 4 (renommage aller-retour entre la copie et l'acquittement : la ligne `role_locked` déjà écrite garde `role_missing` ; état actuel du traitement dans le commentaire de `ppp_ack_pending()`, `worker.c`). La génération d'entrée ajoutée en vérification 4 (constat 2) ne change rien à ces limites : elle distingue une entrée évincée puis recréée, pas un rôle renommé ou recréé.
- **Double formatage des logs web** : le filtre de masquage du web (`web/app/logfilter.py`) formate lui-même un enregistrement susceptible de contenir un secret, que son handler formate une seconde fois ; surcoût limité à ces enregistrements, accepté en échange du masquage avant tout handler (relève de `web/`).
- **Vérification bcrypt à chaque requête web (authentification basic)** : chaque requête refait `bcrypt.checkpw()` (`web/app/auth.py`), sans cache de session ; coût CPU accepté pour une interface d'administration à faible trafic, et le travail constant (hachage factice pour un nom inconnu) n'expose pas l'existence d'un compte (relève de `web/`).
- **Éviction anonymisée des avertissements web limités** (vérification 14) : les avertissements limités du web (`_ThrottledWarning`, `web/app/auth.py`) ne suivent que les 256 dernières clés vues (pair normalisé, ou nom refusé dans l'en-tête du proxy) ; au-delà, la clé la plus anciennement vue est oubliée et son compte en attente passe au compteur global « (all sources) », sans plus être attribué à cette clé. Accepté : l'état reste borné face à un balayage depuis de nombreuses adresses, et le comportement est documenté dans `web/README.md` (relève de `web/`).
- **Préflight Vault en deux requêtes** : maintenu, voir plus haut (CLI).
- **Oracle d'existence et de profil par la durée du verrou** : un attaquant qui verrouille un nom lit dans le DETAIL « locked until … » (ou « until manual unlock ») une durée qui révèle que le rôle existe et quel profil il porte, les noms inexistants imitant le profil `default` ; c'est la conséquence des profils par rôle, au prix de `max_failures` tentatives par nom. Pour fermer cette fuite, garder `lock_duration` et `max_failures` identiques entre profils (option non implémentée : ne pas annoncer la date de fin dans le DETAIL).
- **Profil `default` modifiable par un admin non superutilisateur** (vérification 5) : `alter_profile()` et `assign_profile()` restent ouvertes à `pass_policy_admin` (option A, §11 « (revue) `_require_target_allowed()` »). En modifiant le profil `default`, un tel admin agit aussi sur les superutilisateurs qui n'ont pas de profil propre : `max_age` et `grace_period` (`VALID UNTIL` synchronisé par `run_maintenance()`, étape d), `max_failures` et `lock_duration` (verrouillage). Il peut donc rendre un superutilisateur inutilisable sans pouvoir le viser directement (`rotate_password()`, `lock_role()`… le refusent). Mitigation : `pg_pass_policy.exempt_roles` (recommandé : `'postgres'`), qui soustrait ces rôles à la politique, à la synchronisation de `VALID UNTIL` et au verrouillage. Choix assumé : réserver `default` aux superutilisateurs priverait l'admin délégué du réglage le plus courant.
- **Points de style non traités** (vérification 5) : `_rotate_role()` appelle `_refresh_role_state(p_oid)` après `_ensure_recorded()`, alors que `_record_password_change()` vient d'écrire `expires_at` et `grace_until` d'après le même profil effectif ; l'appel est redondant (au pire une mise à jour sans ligne modifiée) et gardé comme garde-fou peu coûteux.

### Constats résiduels de la relecture finale de la CLI (non traités, acceptés)

- `pgpp check` ouvre `/dev/stdin` pour lire le mot de passe au terminal : sans `/proc` monté (chroot minimal), l'ouverture échoue et la commande sort en code 2 ; le mot de passe peut alors être fourni par un tube. Choix retenu pour fonctionner sans terminal de contrôle (`setsid`).
- Si le processus parent ignore SIGINT (`trap '' INT`), un Ctrl-C à l'invite est signalé comme erreur d'usage (code 2) plutôt que par le signal : cas marginal, documenté.
- `repeated_mount_warning` dépend d'une garde chez l'appelant ; le lancement de `sh` pour la vérification du shell est synchrone dans `Delivery::prepare` (latence seulement, un seul flux dans la CLI ; un nom `localhost` n'est plus résolu, il est épinglé sur `127.0.0.1` selon la RFC 6761) ; `run()` pré-calcule trois entrées par trois `match` successifs. Points de style, sans effet sur le comportement.
- **Double évaluation de `v_role_status` dans `pgpp expiring --within`** (vérification 10) : la requête lit `v_role_status` et évalue `v_expiring` en sous-requête (`role_oid IN (SELECT … FROM v_expiring)`), soit deux passages sur la vue. L'extension n'expose pas le filtre de `v_expiring` sous une autre forme, et le recopier dans `pgpp` (une seule lecture) a été refusé à la revue précédente : un changement de ce filtre dans l'extension s'applique tel quel. Coût accepté : la vue compte une ligne par rôle de connexion et n'est lue qu'à la demande ; le test d'intégration vérifie que toute ligne de `v_expiring` est listée.
- **Diagnostic d'installation sauté dans une transaction** (vérification 13) : quand `commands::diagnose` reçoit une erreur de schéma alors que la connexion est encore dans une transaction, il ne lance pas le contrôle `extension_version` (la transaction est déjà en échec) et ajoute seulement `UNVERIFIED_INSTALLATION (inside a transaction)`. Contrat documenté : les appelants n'appellent pas `diagnose` dans une transaction ; ce cas de repli n'est qu'une garde, sans annulation ni contrôle.
