# Tests de pg_pass_policy

Trois niveaux de tests :

| niveau | où | quoi |
|---|---|---|
| pg_regress | `test/sql/*.sql`, `test/expected/*.out` | API SQL, hook de complexité, historique, rotation, maintenance, droits |
| shell | `test/shell/*.sh` | vraies connexions TCP/SCRAM : verrouillage, expiration, NOTIFY, worker |
| matrice Docker | `docker/` | les deux niveaux précédents sur PostgreSQL 14, 15, 16, 17 et 18 |

## 1. pg_regress

### Pourquoi pas `make check` ni `make installcheck` « nu »

`pg_pass_policy` doit être chargée par `shared_preload_libraries` : les tests
exigent donc une instance démarrée avec `test/pg_pass_policy.conf`, jamais
l'instance de développement courante.

- `make check` **n'est pas pris en charge par PGXS** : il affiche
  `"make check" is not supported` et **renvoie 0** (aucun test n'est lancé).
- `make installcheck` seul se connecte à l'instance qui écoute sur le port par
  défaut (celle du poste) : refusé ici, cette instance n'a pas la bibliothèque
  préchargée et on ne veut pas y créer de rôles de test.
- La bonne commande est `make installcheck` **avec `--temp-instance`** :
  pg_regress crée alors une instance jetable (initdb, `--temp-config`, port libre,
  socket dans un répertoire temporaire) avec les binaires du `PG_CONFIG` choisi.

```sh
make PG_CONFIG=/chemin/vers/pg_config
make PG_CONFIG=/chemin/vers/pg_config install
make PG_CONFIG=/chemin/vers/pg_config installcheck
# en cas d'échec :
less test/regression.diffs
```

Le `Makefile` place déjà `--temp-instance=test/tmp_check` dans `REGRESS_OPTS`
(et `test/tmp_check` dans `EXTRA_CLEAN`) : `make installcheck` suffit, aucune
instance n'est laissée en route. La cible `make test` enchaîne `make install`,
`make installcheck` et `test/shell/run-all.sh`.

La base de test s'appelle `contrib_regression` (ajoutée par PGXS) : c'est la
valeur de `pg_pass_policy.database` dans `test/pg_pass_policy.conf`.

### Configuration de test

`test/pg_pass_policy.conf` fixe `pg_pass_policy.worker_interval = 0` : le worker
est démarré mais ne fait aucun tour périodique, si bien que seules les
invocations explicites de `run_maintenance()` agissent et que les sorties sont
reproductibles. Le comportement du worker est vérifié par les tests shell.

Remarque : `run_maintenance()` appelle `shmem_reload()`, qui peut réveiller le
worker pour un tour. Les tests ne dépendent que de l'état final (pas du nombre
exact d'actions renvoyées par `run_maintenance()`).

### Conventions des scénarios

- rôles de test préfixés `regress_` (convention pg_regress), supprimés dans
  `99_teardown` ;
- `\set VERBOSITY terse` en tête de chaque fichier ;
- les mots de passe n'apparaissent que dans le texte des commandes : les
  résultats ne montrent que des booléens, longueurs et codes `PPP-xxx` ;
- les mots de passe générés (`rotate_password`, `switch_rotation_pair`) sont
  capturés par `INSERT INTO ppp_test.secrets SELECT …` : ils ne sont ni
  affichés ni présents dans le texte d'une requête ;
- aucun horodatage affiché (pg_regress impose `PGTZ=PST8PDT` et
  `DateStyle=Postgres`) ; les durées sont comparées avec une tolérance ;
- schéma utilitaire `ppp_test` (créé dans `00_setup`) :
  - `ppp_test.try(sql)` : exécute et renvoie `ok` ou `SQLSTATE [PPP-xxx]`,
    pour ne pas dépendre du libellé exact des messages ;
  - `ppp_test.code(motif)` : extrait `PPP-xxx` d'un résultat de `check_password` ;
  - `ppp_test.secrets` : tous les mots de passe connus des tests ;
  - `ppp_test.leaks()` : nombre de lignes d'audit/historique contenant un secret
    connu (≥ 10 caractères) ou un vérificateur ; appelée à la fin de presque
    chaque fichier, doit valoir 0.
- `SET SESSION AUTHORIZATION` (et non `SET ROLE`) pour jouer un autre rôle :
  les fonctions d'administration contrôlent `session_user`.

### Liste des tests

| fichier | couvre |
|---|---|
| `00_setup` | `CREATE EXTENSION`, tables/vues/colonnes, fonctions (langage, `SECURITY DEFINER`), aucun droit `PUBLIC`, rôles `pass_policy_admin`/`pass_policy_viewer`, profil `default` (valeurs SPEC §3.1), dictionnaire, tous les GUC et leur contexte, `worker_status()`, rôle `regress_legacy` créé avant l'extension (statut `unknown`) |
| `10_profile` | `create/alter/drop_profile`, clés jsonb inconnues ou techniques, valeur invalide, tentative d'injection dans une clé, `assign/unassign_profile`, `effective_profile` (default par défaut, rôle inconnu), audit `profile_assigned`, refus de supprimer `default` ou un profil affecté |
| `20_complexity` | chaque code `PPP-001`, `PPP-010` → `PPP-020` via `check_password` puis via de vrais `ALTER ROLE` (SQLSTATE 28P01), cas limites acceptés (12 et 128 caractères, 3 répétitions, espace interne), `check_password` sans effet de bord, `CREATE ROLE … PASSWORD` (refus et acceptation, OID complété après maintenance), `load_dictionary` insensible à la casse, colonne `word_sha256` cohérente avec les mots (mot contenant `\`, recherche du hook par digest), profil assoupli, pré-haché SCRAM accepté si `reject_prehashed = false`, `require_scram` (MD5 pré-haché, `password_encryption = md5`), `enforce_database` (`\c postgres`, code `PPP-003`) |
| `30_history` | `history_count = 3` (troncature, réutilisation `PPP-031`, sortie de l'historique), `history_count = 0`, `history_days`, `min_age` (`PPP-030`) pour un non-superutilisateur qui change son propre mot de passe, contournement par superutilisateur, complexité appliquée au changement par soi-même, rôle supprimé puis recréé sous le même nom (ni `PPP-030` ni `PPP-031` hérités de l'ancien rôle), `CREATE ROLE … PASSWORD` comparé aux seules lignes sans OID, `CREATE ROLE … PASSWORD` puis `ALTER ROLE` sans `run_maintenance()` (ligne sans OID comparée : `PPP-031` ; `min_age` compté depuis cette ligne : `PPP-030`), historique 100 % SCRAM bien formé et sans clair |
| `40_generate` | longueurs (défaut 24, 8 et 512 avec un profil large), bornes absolues (< 8, > 512) et bornes du profil, 200 tirages : 4 classes, aucun caractère ambigu `0O1lI|`, ASCII imprimable sans espace, tous distincts, conformes (`check_password` NULL) ; minima par classe d'un profil exigeant ; aucune écriture d'audit |
| `50_rotation` | `rotate_password` : longueur, classes, mot de passe effectivement en place (réutilisation détectée), `role_state` (+30 j, +7 j), `rolvaliduntil = grace_until`, audit `password_rotated` sans le mot de passe, acteur ; longueur 32 ; erreurs ; nom de rôle à guillemets ; `expire_password` (must_change, VALID UNTIL, statut `expired`, `v_expiring`, audit) puis rotation qui remet en état |
| `55_pair` | `create_rotation_pair` (groupe inexistant, rôle existant/créé, LOGIN, INHERIT, membres, doublon), trois `switch_rotation_pair` (alternance, `previous_valid_until` borné par `grace_period`, appliqué à `rolvaliduntil`, `rotation_pair` à jour), ancien rôle borné dans `role_state` (statut `grace`) et toujours borné après `DELETE FROM rotation_pair` + `run_maintenance()`, filet de l'étape a (paire purgée parce que le groupe a disparu), audit `pair_switched`, paire inconnue |
| `60_lock_unlock` | `lock_role` manuel (valeur renvoyée `infinity` ou `now() + durée`, `manual`, raison, `v_locked`, statut `locked`, shmem via `failed_attempts()`, audit), re-verrouillage, `unlock_role` (role_state, vue, shmem, audit), verrou de 1 s levé par `run_maintenance`, rôles inconnus, fonctions `shmem_*` |
| `70_maintenance` | `expiry_warning` + `last_warned_at`, `expires_at`/`grace_until`, statuts `expired`/`grace`/`warning`/`never_expires`, `v_expiring`, `rolvaliduntil` et `valid_until_synced`, `password_expired` non dupliqué, valeur de retour sans secret, resynchronisation après `alter_profile`, purge d'un rôle supprimé, renommage puis recréation de l'ancien nom (verrou, profil et historique suivent l'OID ; avant la maintenance, `v_locked` joint `role_state` par OID et `v_role_status.role_oid`), `role_state.role_name` rafraîchi par `lock_role`/`unlock_role`/`expire_password` après un renommage, déverrouillage automatique d'un rôle renommé (verrou réinjecté par le worker sous le nouveau nom, shmem, audit `role_unlocked` et `role_state` au nom courant), réconciliation du rôle antérieur à l'extension et d'un changement fait avec `enabled = off` (via `ALTER SYSTEM` + `pg_reload_conf()` : `enabled` est de contexte SIGHUP, `SET` est refusé), `manage_valid_until = off` : `VALID UNTIL` posé par `expire_password` relevé à `infinity` (mode `unblock`) après changement du mot de passe, pas de `VALID UNTIL` posé par `rotate_password` ni par `switch_rotation_pair`, verrou consultatif de `run_maintenance()` (deux passes dans une transaction, relâché au COMMIT) |
| `80_audit` | `audit()` (acteur, base, détails, défaut `{}`, rôle NULL, type inconnu refusé), `v_recent_audit` limitée à 1000, `purge_audit` (défaut 365 j, seuil personnalisé), types d'événements ⊂ SPEC §3.6, aucun `PASSWORD `, `ALTER ROLE`, secret ni vérificateur dans l'audit |
| `90_privileges` | utilisateur ordinaire : toutes les fonctions d'administration, `audit()`, `shmem_*`, `record_password_change` (autre rôle et soi-même), lecture/écriture des tables et vues → 42501 ; viewer : vues et tables en lecture, aucune écriture ni administration ; admin non superutilisateur : administration OK, mais pas sur un superutilisateur ni sur un rôle membre (direct, transitif) d'un superutilisateur ou de `pg_execute_server_program`, ni `create_rotation_pair` sur un tel groupe (et le `CREATE ROLE` est annulé) ; groupe ordinaire propriétaire de la base accepté ; en superutilisateur les mêmes appels réussissent ; aucun droit `PUBLIC` (schéma, `effective_profile`, `audit`, `record_password_change`) mais un utilisateur ordinaire change son propre mot de passe (politique appliquée, changement enregistré) ; `check_password` d'un admin sur un autre rôle sans `min_age` ; schéma re-possédé par un non-superutilisateur → `PPP-004` (hook et `check_password`) ; `exempt_roles` : `_is_exempt()` (fonction C des hooks) sur des noms quotés, non quotés, avec espaces et `""`, attente du rechargement bornée à 5 s (`\gexec`), concordance `_is_exempt()` / hook, rôle exempté sans `VALID UNTIL` posé par `rotate_password`, `VALID UNTIL` posé par `expire_password` relevé par `run_maintenance()` (mode `unblock`) après un `ALTER ROLE` direct ; faux schéma `pass_policy` dans une autre base |
| `99_teardown` | `DROP EXTENSION` (le schéma `pass_policy`, vide, survit : il est déclaré par la clé `schema` du `.control` et n'appartient pas à l'extension), `DROP SCHEMA pass_policy` manuel, rôles admin/viewer conservés, suppression des rôles `regress_%`, réinstallation avec rôles déjà présents, suppression finale extension + schéma |

LISTEN/NOTIFY n'est pas testable en pg_regress (psql affiche le PID émetteur et
un horodatage) : voir `test/shell/notify.sh`.

### Régénérer les fichiers attendus

Les fichiers `test/expected/*.out` ont été produits sur PostgreSQL 16.4 avec
l'état du code au moment de l'écriture des tests, puis relus. **Ils doivent être
revus à chaque changement de comportement** :

```sh
make PG_CONFIG=… installcheck
less test/regression.diffs          # relire chaque différence
cp test/results/X.out test/expected/X.out   # seulement après revue, test par test
```

Ne jamais copier les résultats sans lire le diff : un `f` à la place d'un `t`
ou un code PPP différent est un bogue, pas une mise à jour.

Le schéma `pass_policy` survit à `DROP EXTENSION` (clé `schema` du `.control`,
comportement standard de PostgreSQL) : `99_teardown` le constate puis le
supprime à la main avec `DROP SCHEMA pass_policy`.

## 2. Tests shell

Chaque script démarre sa propre instance temporaire (`test/shell/common.sh`) :
`initdb` dans `mktemp -d`, port TCP libre (54400-54899 ; cette plage est dans
la plage éphémère de Linux, un port peut donc être occupé côté client par une
connexion d'un test précédent : en cas de « Address already in use » au
démarrage, un autre port est tiré, 5 essais au plus), `listen_addresses =
127.0.0.1`, pas de socket Unix, configuration = `test/pg_pass_policy.conf` + surcharges
(`pg_pass_policy.database = postgres`, `worker_interval = 2`,
`log_connections = on`), `pg_hba.conf` : superutilisateur de test en `trust`,
tous les autres rôles en `scram-sha-256`. L'instance est arrêtée par un `trap
EXIT` (y compris sur échec ou Ctrl-C) ; le log serveur est affiché en cas
d'échec.

```sh
make PG_CONFIG=… install                 # préalable, non fait par les scripts
PG_CONFIG=… test/shell/run-all.sh        # tous les scripts, récapitulatif
PG_CONFIG=… test/shell/lockout.sh        # un seul script
PPP_KEEP_TMP=1 PG_CONFIG=… test/shell/expiry.sh   # conserve données + log
```

| script | couvre |
|---|---|
| `lockout.sh` | (instance avec `fsync = on`) rechargement shmem par le worker après `assign_profile` et application effective des nouveaux paramètres (`max_failures = 2`), 5 échecs puis refus « locked » même avec le bon mot de passe, `failed_attempts()`, audit `role_locked`/`auth_failed` et `role_state` écrits par le worker, déverrouillage automatique après `lock_duration = 5 s`, remise à zéro du compteur après un succès, verrou expiré avant le passage du worker (`worker_interval = 60` : audit conservé, reverrouillage après 5 nouveaux échecs), `failure_window`, `lock_duration` de 100 ans (pas d'« integer out of range ») et NULL (`infinity`), `lock_role`/`unlock_role` manuels persistants après un tour du worker, `lock_role`/`unlock_role` sous `ROLLBACK` et `SAVEPOINT` (shmem appliquée au COMMIT seulement), `exempt_roles`, échecs sur rôle inexistant, verrou automatique récent conservé par `run_maintenance()` (verrou expiré dans `role_state`), une seule ligne `auth_failed` agrégée pour les noms inexistants, échecs `ident` et refus `reject` (par rôle, par base) non comptés, aucun échec de cycle du worker |
| `hashfull.sh` | `max_tracked_roles = 16`, `worker_interval = 3600` (worker réveillé seulement par `shmem_reload()`) : 24 noms inexistants occupent les 16 entrées sans LOG « cannot track », 5 échecs sur un vrai rôle le verrouillent aussitôt (sans tour du worker), un nom inexistant est « locked » après 5 échecs avec la même réponse qu'un vrai rôle, `lock_role` appliqué sur un hash plein de fantômes (`failed_attempts()` et `role_state` cohérents), verrou conservé après un tour du worker et réinjecté après redémarrage avec le hash rempli, purge des noms inexistants après `failure_window`, hash plein de verrous réels → `lock_role` lève l'ERROR 53400 et la transaction est annulée (ligne `role_state` inchangée, pas d'audit), LOG « cannot track » au plus une fois par seconde, `unlock_role` libère une place, profils sur 15 rôles sur 16 → un 16e rôle sans profil est compté et verrouillé |
| `standby.sh` | primaire + standby en streaming (`pg_basebackup -R`, second port) : worker actif sur le standby, `lock_role` (permanent et temporisé) et verrou automatique du primaire appliqués sur le standby en au plus 2 tours, `unlock_role` du primaire → accepté sur le standby, profil répliqué appliqué aux échecs comptés sur le standby (verrou local qui survit au rechargement, levé par `shmem_unlock_role()`), hash du standby (`max_tracked_roles = 16`) plein de verrous expirés non audités : le rôle suivant est compté et verrouillé (éviction journalisée), aucun échec de cycle du worker en lecture seule, échecs et verrou local non acquittés sur le standby puis, après `pg_ctl promote`, copiés dans `role_state` et `audit_log` (`role_locked`, `auth_failed`) par le nouveau primaire |
| `expiry.sh` | `max_age = 1 s` : le worker pose `rolvaliduntil = grace_until`, connexion refusée (côté client « password authentication failed », côté serveur « has an expired password »), audit `password_expired`, `v_role_status`/`v_expiring`, connexion avec le mot de passe de `rotate_password`, **absence du mot de passe généré dans le log serveur**, `expire_password` non annulé par le worker, rôle expiré non verrouillé par 6 tentatives avec le bon mot de passe |
| `notify.sh` | NOTIFY dans la même session (déterministe) et dans une autre session (écouteur en `pg_sleep`), charge utile JSON `event`/`role`/`at`/`details`, absence de mot de passe et de vérificateur, absence du mot de passe dans le log serveur, canal personnalisé `notify_channel`, refus `PPP-010` (direct, via `EXECUTE`, via `_set_password`) et ERROR de `check_password()` dans une base sans l'extension : mot de passe absent du log serveur |
| `auto_explain.sh` | instance avec `auto_explain` (`log_min_duration = 0`, `log_nested_statements = on`, `log_verbose = on`) : `rotate_password`, `switch_rotation_pair`, `ALTER ROLE … PASSWORD`, `run_maintenance` + tour du worker → aucun mot de passe ni `SCRAM-SHA-256$` dans le log serveur, auto_explain bien actif par ailleurs |
| `scs_off.sh` | `standard_conforming_strings = off` dans `postgresql.conf` : `CREATE EXTENSION` réussit, mots du dictionnaire avec un et deux antislashs (condensat des octets bruts, `PPP-018` par `check_password` et `ALTER ROLE`) |
| `unicode.sh` | instance en `C.UTF-8` (`PPP_LOCALE`, ignoré si la locale manque) : `PPP-018` et `PPP-017` insensibles à la casse sur des lettres non ASCII (`Été` / `été`), via `check_password` et par un vrai `ALTER ROLE`, mot de passe non ASCII accepté et absent du log |

Le mauvais mot de passe est toujours fourni explicitement (`PGPASSWORD`) : une
connexion abandonnée avant l'envoi du mot de passe n'est pas comptée comme un
échec (SPEC §11). PostgreSQL n'indique jamais au client que le mot de passe a
expiré : `expiry.sh` le vérifie dans le log serveur.

Locale : les scripts shell forcent `initdb --locale=C` (variable `PPP_LOCALE`
pour changer, `unicode.sh` la met à `C.UTF-8`), alors que pg_regress hérite de
`LANG` de l'environnement : les tests pg_regress n'utilisent donc que des mots
de passe ASCII pour le dictionnaire et le nom de rôle.

## 3. Matrice Docker (PostgreSQL 14 → 18)

`docker/Dockerfile` (`ARG PG_MAJOR`, `ARG DEBIAN_SUITE=bookworm`) part de
`postgres:${PG_MAJOR}-bookworm`, installe `build-essential`, `libkrb5-dev`
(les en-têtes PGDG `libpq/libpq-be.h` incluent `gssapi/gssapi.h`) et
`postgresql-server-dev-${PG_MAJOR}`, compile et installe l'extension en root
puis lance `docker/test-in-container.sh` en utilisateur `postgres` :
`make installcheck TEMP_INSTANCE=/tmp/ppp_regress` puis
`test/shell/run-all.sh`. Pas de volume : `/tmp` est un tmpfs jeté à la fin.
`TEMP_INSTANCE` (variable du `Makefile`, défaut `test/tmp_check`) place
l'instance temporaire de pg_regress dans ce tmpfs : la couche overlay du
conteneur peut être presque pleine (Docker Desktop) et `initdb` y échouer sur
« No space left on device ». Chaque image fait environ 1,4 Go : sur un disque
Docker étroit, construire et tester une version à la fois puis
`docker rmi pg_pass_policy-test:NN` et `docker builder prune`.

Les tags `postgres:14-bookworm` … `postgres:18-bookworm` existent (vérifié par
`docker manifest inspect` en octobre 2026 ; `18-trixie` existe aussi :
`DEBIAN_SUITE=trixie` pour l'utiliser).

```sh
docker compose -f docker/compose.yml config        # validation
docker compose -f docker/compose.yml build pg17
docker compose -f docker/compose.yml run --rm pg17
docker/run-all.sh                 # 14 → 18 séquentiel, récapitulatif PASS/FAIL
docker/run-all.sh -j              # en parallèle
docker/run-all.sh 16 18           # sous-ensemble
```

Journaux par version dans `docker/logs/pgNN.log` ; code retour non nul si une
version échoue. `docker/Dockerfile.dockerignore` exclut les objets compilés,
les résultats de test et les répertoires `cli/target`, `web/.venv`.
