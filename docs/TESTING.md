# Tests de pg_pass_policy

Trois niveaux de tests :

| niveau | où | quoi |
|---|---|---|
| pg_regress | `test/sql/*.sql`, `test/expected/*.out` | API SQL, hook de complexité, historique, rotation, maintenance, droits |
| shell | `test/shell/*.sh` | vraies connexions TCP/SCRAM : verrouillage, expiration, NOTIFY, worker |
| matrice Docker | `docker/` | les deux niveaux précédents sur PostgreSQL 14, 15, 16, 17 et 18 |

Les tests de la CLI et du back-office web sont décrits dans leurs dépôts :
[`pg_pass_policy-cli`](https://github.com/gliatti/pg_pass_policy-cli#tests) et
[`pg_pass_policy-web`](https://github.com/gliatti/pg_pass_policy-web#tests).

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
| `20_complexity` | chaque code `PPP-001`, `PPP-010` → `PPP-020` via `check_password` puis via de vrais `ALTER ROLE` (SQLSTATE 28P01), cas limites acceptés (12 et 128 caractères, 3 répétitions, espace interne), `check_password` sans effet de bord, `CREATE ROLE … PASSWORD` (refus et acceptation, OID complété après maintenance), `load_dictionary` insensible à la casse, colonne `word_sha256` cohérente avec les mots (mot contenant `\`, recherche du hook par digest), profil assoupli, pré-haché SCRAM accepté si `reject_prehashed = false`, `require_scram` (MD5 pré-haché, `password_encryption = md5`), `enforce_database` (`\c postgres`, code `PPP-003`) ; (vérification 6) `check_password` aligné sur le hook : vérificateur pré-haché soumis à `min_age` (`PPP-030` pour les deux), `superuser_bypass = on` (mot de passe faible accepté par le hook ; vérification 7 : `check_password` l'ignore et répond `PPP-010`) |
| `30_history` | `history_count = 3` (troncature, réutilisation `PPP-031`, sortie de l'historique), `history_count = 0`, `history_days`, `min_age` (`PPP-030`) pour un non-superutilisateur qui change son propre mot de passe, contournement par superutilisateur, dans le hook comme dans `check_password()` (vérification 9 : même réponse pour le même appelant), complexité appliquée au changement par soi-même, rôle supprimé puis recréé sous le même nom (ni `PPP-030` ni `PPP-031` hérités de l'ancien rôle), `CREATE ROLE … PASSWORD` comparé aux seules lignes sans OID, `CREATE ROLE … PASSWORD` puis `ALTER ROLE` sans `run_maintenance()` (ligne sans OID comparée : `PPP-031` ; `min_age` compté depuis cette ligne : `PPP-030`), historique 100 % SCRAM bien formé et sans clair |
| `40_generate` | longueurs (défaut 24, 8 et 512 avec un profil large), bornes absolues (< 8, > 512) et bornes du profil, 200 tirages : 4 classes, aucun caractère ambigu `0O1lI|`, ASCII imprimable sans espace, tous distincts, conformes (`check_password` NULL) ; minima par classe d'un profil exigeant ; aucune écriture d'audit ; (vérification 6) `_generate_password_for('abc', 512, …)` : 1000 tirages sans `abc`/`cba` (alors que `generate_password` en produit), aucun `PPP-017`, 20 rotations du rôle `abc` acceptées |
| `50_rotation` | `rotate_password` : longueur, classes, mot de passe effectivement en place (réutilisation détectée), `role_state` (+30 j, +7 j), `rolvaliduntil = grace_until`, audit `password_rotated` sans le mot de passe, acteur ; longueur 32 ; erreurs ; nom de rôle à guillemets ; `expire_password` (must_change, VALID UNTIL, statut `expired`, `v_expiring`, audit) puis rotation qui remet en état |
| `55_pair` | `create_rotation_pair` (groupe inexistant, rôle existant/créé, LOGIN, INHERIT, membres, doublon), trois `switch_rotation_pair` (alternance, `previous_valid_until` borné par `grace_period`, appliqué à `rolvaliduntil`, `rotation_pair` à jour), ancien rôle borné dans `role_state` (statut `grace`) et toujours borné après `DELETE FROM rotation_pair` + `run_maintenance()`, filet de l'étape a (paire purgée parce que le groupe a disparu), audit `pair_switched`, paire inconnue ; (vérification 6) `manage_valid_until = off`, trois bascules rapides : le rôle redevenu actif n'a plus de borne (mode `release`), l'ancien reste borné ; (vérification 7) `rotate_password()` avec `manage_valid_until = off` : borne de paire conservée, borne future écrite par l'extension levée, borne future posée à la main conservée |
| `60_lock_unlock` | `lock_role` manuel (valeur renvoyée `infinity` ou `now() + durée`, `manual`, raison, `v_locked`, statut `locked`, shmem via `failed_attempts()`, audit), re-verrouillage, `unlock_role` (role_state, vue, shmem, audit), verrou de 1 s levé par `run_maintenance`, rôles inconnus, fonctions `shmem_*`, `shmem_lock_role()` d'un nom sans rôle → `42704` (vérification 12), puis renommage dans la même transaction → COMMIT accepté, verrou sur l'OID capturé à l'appel, affiché sous le nouveau nom (`role_oid`), `shmem_unlock_role()` de l'ancien nom sans effet, du nouveau effectif ; `lock_role()` puis renommage : `failed_attempts()` et `v_role_status` sous le nouveau nom, `unlock_role()` du nouveau nom ; `_shmem_lock()` d'un OID sans rôle → `42704` ; colonnes de `failed_attempts()` avec `role_oid` (vérification 15) ; (vérification 16) OID 0 : `_shmem_unlock()`, `_shmem_reset()`, `_shmem_is_locked()` → `22023` « invalid role OID » (le backend plantait avec `542b010`), `_shmem_lock()` → `42704` |
| `70_maintenance` | `expiry_warning` + `last_warned_at`, `expires_at`/`grace_until`, statuts `expired`/`grace`/`warning`/`never_expires`, `v_expiring`, `rolvaliduntil` et `valid_until_synced`, `password_expired` non dupliqué, valeur de retour sans secret, resynchronisation après `alter_profile`, purge d'un rôle supprimé, renommage puis recréation de l'ancien nom (verrou, profil et historique suivent l'OID ; avant la maintenance, `v_locked` joint `role_state` par OID et `v_role_status.role_oid`), `role_state.role_name` rafraîchi par `lock_role`/`unlock_role`/`expire_password` après un renommage, déverrouillage automatique d'un rôle renommé (verrou réinjecté par le worker sous le nouveau nom, shmem, audit `role_unlocked` et `role_state` au nom courant), réconciliation du rôle antérieur à l'extension et d'un changement fait avec `enabled = off` (via `ALTER SYSTEM` + `pg_reload_conf()` : `enabled` est de contexte SIGHUP, `SET` est refusé), `manage_valid_until = off` : `VALID UNTIL` posé par `expire_password` relevé à `infinity` (mode `unblock`) après changement du mot de passe, pas de `VALID UNTIL` posé par `rotate_password` ni par `switch_rotation_pair`, verrou consultatif de `run_maintenance()` (deux passes dans une transaction, relâché au COMMIT) ; (vérifications 15 à 17) lignes restaurées (`cluster_id = 42`), inertes jusqu'à l'étape a0 : sans effet dans `v_role_status` avant la maintenance ; rattachement par le nom (`role_state` et `role_profile`), fusion avec la ligne locale (`merged`, verrou le plus long), rattachement par l'OID quand aucun rôle ne porte le nom (pg_upgrade + renommage) ; ligne locale à OID disparu, rôle recréé sous le même nom : purgée, pas de remappage ; ligne non résolue comptée (`unbound`) ; (vérification 17) (a) `ALTER ROLE … PASSWORD` avec des lignes restaurées présentes (l'une à l'OID local du rôle sous un autre nom, l'autre à son nom) : `xmin` inchangé, aucun `remap`, rôle non verrouillé ; (b) ligne non résolue conservée par deux passes et par `rebind_restored_roles()`, supprimée et journalisée (`purge`) par `rebind_restored_roles(p_purge_unresolved => true)` seulement ; (c) OID croisés de deux rôles : verrou et profil rattachés par le nom ; (d) fusion : `password_changed_at`, `expires_at` et `grace_until` locaux conservés, verrou le plus long, `must_change` ; `lock_role()` d'un rôle dont l'OID porte une ligne restaurée d'un autre nom : ligne restaurée intacte, rattachée ensuite par le nom ; limite pg_upgrade (OID existant sous un autre nom, nom porté par un autre rôle) : rattachée au rôle du nom ; (a) à (d) échouent avec `0fcfba4` ; (vérification 6) colonnes `is_exempt`, `expiry_state`, `valid_until` de `v_role_status`, rôle expiré puis verrouillé : `status = locked`, `expiry_state = expired`, présent dans `v_expiring` |
| `80_audit` | `audit()` (acteur, base, détails, défaut `{}`, rôle NULL, type inconnu refusé), `v_recent_audit` limitée à 1000, `purge_audit` (défaut 365 j, seuil personnalisé), types d'événements ⊂ SPEC §3.6, aucun `PASSWORD `, `ALTER ROLE`, secret ni vérificateur dans l'audit |
| `90_privileges` | utilisateur ordinaire : toutes les fonctions d'administration, `audit()`, `shmem_*`, `record_password_change` (autre rôle et soi-même), lecture/écriture des tables et vues → 42501 ; viewer : vues et tables en lecture, aucune écriture ni administration ; admin non superutilisateur : administration OK, mais pas sur un superutilisateur ni sur un rôle membre (direct, transitif) d'un superutilisateur ou de `pg_execute_server_program`, ni `create_rotation_pair` sur un tel groupe (et le `CREATE ROLE` est annulé) ; groupe ordinaire propriétaire de la base accepté ; en superutilisateur les mêmes appels réussissent ; aucun droit `PUBLIC` (schéma, `effective_profile`, `audit`, `record_password_change`) mais un utilisateur ordinaire change son propre mot de passe (politique appliquée, changement enregistré) ; `check_password` d'un admin sur un autre rôle sans `min_age` ; schéma re-possédé par un non-superutilisateur → `PPP-004` (hook et `check_password`) ; `exempt_roles` : `_is_exempt()` (fonction C des hooks) sur des noms quotés, non quotés, avec espaces et `""`, attente du rechargement bornée à 5 s (`\gexec`), concordance `_is_exempt()` / hook, rôle exempté sans `VALID UNTIL` posé par `rotate_password`, `VALID UNTIL` posé par `expire_password` relevé par `run_maintenance()` (mode `unblock`) après un `ALTER ROLE` direct ; faux schéma `pass_policy` dans une autre base ; (vérification 6) `expire_password` et `lock_role` refusés (22023) pour un rôle exempté, `is_exempt` / `expiry_state` / `valid_until` lus aussi par le viewer ; (vérification 7) même message et même HINT pour les deux refus (`_require_not_exempt()`), rôle exempté : borne future écrite par l'extension levée par `rotate_password()`, borne posée à la main conservée |
| `95_parity` | parité `check_password()` ↔ hook pour le même appelant, dans les deux sens (vérification 9) : superutilisateur juste après un changement (`min_age` ignoré par les deux : `ok \| ok`), réutilisation et complexité (`PPP-031`, `PPP-010` par les deux) ; le rôle lui-même (`PPP-030` par les deux, puis `ok` une fois `min_age` écoulé, `PPP-031`, `ok`) |
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
`log_connections = on`, `pg_pass_policy.exempt_roles` = superutilisateur de
test : la fenêtre de démarrage refuse tout rôle non exempté, `trust` TCP compris),
`pg_hba.conf` : superutilisateur de test en `trust`, tous les autres rôles en
`scram-sha-256`. L'instance est arrêtée par un `trap
EXIT` (y compris sur échec ou Ctrl-C) ; le log serveur est affiché en cas
d'échec.

```sh
make PG_CONFIG=… install                 # préalable, non fait par les scripts
PG_CONFIG=… test/shell/run-all.sh        # tous les scripts, récapitulatif
PG_CONFIG=… test/shell/lockout.sh        # un seul script
PPP_KEEP_TMP=1 PG_CONFIG=… test/shell/expiry.sh   # conserve données + log
```

`lockout.sh` dure plus d'une minute : le LOG d'admission de secours est
limité à une ligne par rôle et par `PPP_RESCUE_LOG_SECS` (60 s, constante de
compilation, sans GUC de test), et le test attend réellement 61 s pour
vérifier que le worker journalise ensuite les admissions restées non
journalisées. Une assertion avant et une après l'attente vérifient que la
fenêtre de démarrage est toujours ouverte (`worker_status().locks_loaded =
false`) : si elle s'était refermée pendant l'attente, l'échec est explicite
au lieu d'être intermittent.

| script | couvre |
|---|---|
| `lockout.sh` | (instance avec `fsync = on`) rechargement shmem par le worker après `assign_profile` et application effective des nouveaux paramètres (`max_failures = 2`), 5 échecs puis refus « locked » même avec le bon mot de passe, `failed_attempts()`, audit `role_locked`/`auth_failed` et `role_state` écrits par le worker, déverrouillage automatique après `lock_duration = 5 s`, remise à zéro du compteur après un succès, verrou expiré avant le passage du worker (`worker_interval = 60` : audit conservé, reverrouillage après 5 nouveaux échecs), `failure_window`, `lock_duration` de 100 ans (pas d'« integer out of range ») et NULL (`infinity`), `lock_role`/`unlock_role` manuels persistants après un tour du worker, `lock_role`/`unlock_role` sous `ROLLBACK` et `SAVEPOINT` (shmem appliquée au COMMIT seulement), `exempt_roles`, échecs sur rôle inexistant, verrou automatique récent conservé par `run_maintenance()` (verrou expiré dans `role_state`), une seule ligne `auth_failed` agrégée pour les noms inexistants, échecs `ident` et refus `reject` (par rôle, par base) non comptés, `unlock_role()` d'un verrou automatique sans ligne `role_state` (ligne créée, pas de reverrouillage après le tour du worker), étape f de `run_maintenance()` face à un verrou automatique expiré en attente d'audit (audité sans `lifted_before_audit`), worker suspendu par `enabled = off` (ni audit ni rechargement, audit écrit au retour à `on`), aucun échec de cycle du worker, fenêtre de démarrage (revue finale 7 : rechargement retenté sans SIGHUP avec `worker_interval = 0`, « 4 mauvais + bon + mauvais » toujours `57P03` sans rien compter, `pg_pass_policy.database` inexistante, superutilisateur verrouillé en shmem refusé ; revue finale 8 : superutilisateur non exempté refusé `57P03` pendant une fenêtre normale (worker présent) et accepté seulement worker absent depuis plus de 10 s, LOG (et non WARNING) `worker_pid = 0` une seule fois, sortie du client sans « worker » ni « exempt », relances de 5 s limitées à la synchronisation (`last_run` inchangé), `worker_status().locks_loaded`, schéma `pass_policy` cédé à un non-superutilisateur → WARNING du worker une fois, propriétaire en DETAIL, fenêtre fermée puis rouverte) ; (vérification 6) `failed_attempts()` : noms inexistants nommés pour le superutilisateur seulement, une ligne agrégée (`role_name` NULL) pour un viewer ; rôle verrouillé par une ligne `trust` refusé `57P03` pendant la fenêtre puis « locked » ; (vérification 7, adaptée en 15) pseudo-entrée d'un nom inexistant verrouillé, puis `CREATE ROLE`, `RENAME`, nouveau `CREATE ROLE` : jamais nommée pour le viewer, nommée avec `role_oid` NULL pour le superutilisateur, levée par `shmem_unlock_role()` du nom une fois les rôles supprimés, voie locale de secours pendant la fenêtre (socket Unix ouverte, `pg_ident.conf`) ; (vérification 8) voie restreinte à `rescue_roles` et `peer` : liste vide → superutilisateur en `peer` `57P03` ; liste renseignée (rechargement) → superutilisateur listé accepté en `peer`, refusé « locked » avec un verrou shmem ; superutilisateur listé en `trust` local, superutilisateur non listé en `peer`, rôle ordinaire listé en `peer`, `peer` en échec, `trust` TCP, rôle ordinaire en `trust` local : `57P03` ; aucun HINT sur le `57P03`, ni pour un rôle ordinaire ni pour un superutilisateur, l'information complète étant dans le HINT du LOG serveur (vérification 10) ; LOG d'admission une fois par rôle et par minute : trois admissions, un LOG, un second rôle a le sien, une minute plus tard nouveau LOG avec le nombre d'admissions non journalisées (vérification 10) ; ce nombre écrit par le worker sans admission suivante une fois la minute écoulée, et à la fermeture de la fenêtre pour une admission de la minute en cours, la fenêtre vérifiée ouverte avant et après l'attente de 61 s (vérification 11) ; (vérification 15) trou 1 : verrou automatique en attente puis `RENAME` : nouveau nom refusé avant le tour du worker, puis audité sous le nom courant avec `role_oid`, persisté par OID, toujours refusé ; aucune clé `role_missing`, `role_renamed`, `renamed_to`, `role_recreated` ; trou 2 : cinq échecs sur l'ancien nom : pseudo-entrée distincte verrouillée, le renommé reste verrouillé, rôle créé sous l'ancien nom accepté ; verrou renommé visible sous le nouveau nom, aucun LOG « renamed to » ; verrou persisté, `RENAME` puis `CREATE ROLE` de l'ancien nom : le renommé reste verrouillé, le recréé se connecte ; `shmem_lock_role()`, `DROP ROLE` + `CREATE ROLE` : entrée propre, échec compté ; verrou automatique en attente, `DROP ROLE` + `CREATE ROLE` : nouveau rôle accepté avant le tour du worker, `role_locked` audité avec `role_dropped`, LOG « lock of dropped role … released », pas de verrou dans `role_state` ; compteurs audités ou en attente d'un rôle supprimé : jamais hérités, connexion du rôle recréé acceptée tout de suite ; trou 5 : profil `max_failures = 2` appliqué sous le nouveau nom sans rechargement, rôle recréé aux valeurs par défaut avant et après rechargement ; trou 6 : aucune réponse ni aucun LOG « temporarily locked » ; (vérification 16) viewer : l'entrée d'un rôle supprimé est repliée dans la ligne NULL (ni dernier nom ni ancien OID), le superutilisateur la voit sous son dernier nom ; (vérification 17) lignes restaurées (`cluster_id = 42`, `worker_interval = 0`) : v17 (e) le rechargement n'écrit rien (empreinte `xmin` comprise) et n'applique pas le verrou d'une ligne restaurée, WARNING « 1 row restored from another cluster is not bound » une seule fois pour deux rechargements ; `run_maintenance()` la rattache, verrou appliqué, levé par `unlock_role()` ; v17 (f) scénario `dba`/`bob` de la revue de sécurité (admin non superutilisateur, `regress_bob` ordinaire, `regress_dba` superutilisateur, ligne restaurée verrouillée de `regress_dba` à l'OID local de `regress_bob`) : ni l'un ni l'autre verrouillé avant la maintenance, `unlock_role('regress_bob')` par l'admin et `ALTER ROLE regress_bob PASSWORD` par `regress_bob` laissent la ligne intacte sans `remap` ; `run_maintenance()` la rattache par le nom à `regress_dba`, verrouillé en shmem et dans `role_state`, `regress_bob` non, `unlock_role('regress_dba')` refusé à l'admin |
| `hashfull.sh` | `max_tracked_roles = 16`, `worker_interval = 3600` (worker réveillé seulement par `shmem_reload()`) : 24 noms inexistants occupent les 16 entrées sans LOG « cannot track », 5 échecs sur un vrai rôle le verrouillent aussitôt (sans tour du worker), un nom inexistant est « locked » après 5 échecs avec la même réponse qu'un vrai rôle, `lock_role` appliqué sur un hash plein de fantômes (`failed_attempts()` et `role_state` cohérents), verrou conservé après un tour du worker et réinjecté après redémarrage avec le hash rempli, purge des noms inexistants après `failure_window`, hash plein de verrous réels → `lock_role` lève l'ERROR 53400 et la transaction est annulée (ligne `role_state` inchangée, pas d'audit), LOG « cannot track » au plus une fois par seconde, `unlock_role` libère une place, profils sur 15 rôles sur 16 → un 16e rôle sans profil est compté et verrouillé, verrou automatique remplacé par `lock_role()` → `replaced_by_manual`, y compris quand le verrou manuel a déjà expiré au passage du worker (revue finale 8), rôles supprimés dont les compteurs vivants remplissaient le hash : le worker retire leurs entrées (OID disparu) et l'échec d'un autre rôle est de nouveau compté (vérifications 9 et 15), verrou automatique permanent audité d'un rôle supprimé : entrée retirée du hash au tour suivant du worker avec un LOG, place libérée, rôle recréé sous le même nom accepté sans verrou hérité, la ligne `role_state` étant déjà purgée par la maintenance (vérification 11, qui remplace le fantôme de la vérification 10), pseudo-verrou d'un nom inventé puis `CREATE ROLE` de ce nom : connexion réussie tout de suite, audit en attente ou non (vérification 15), 599 verrous persistés pour 16 places → fenêtre de démarrage maintenue (LOG une fois par minute, `locks_loaded` faux, nouvelles tentatives) puis connexion acceptée une fois les verrous levés ; rechargement seul, sans maintenance (`worker_interval = 0`, redémarrage, vérifications 12 à 17) : lignes restaurées (`cluster_id = 42`) inchangées par le rechargement (`xmin` compris), WARNING « 4 rows restored from another cluster are not bound », fenêtre fermée, aucun verrou tiré d'une ligne inerte (rôles du nom connectés) ni d'une ligne locale à OID disparu, trou 3 : verrou persisté par `lock_role()`, `DROP ROLE` + `CREATE ROLE` puis redémarrage → le nouveau rôle se connecte ; `run_maintenance()` : lignes rattachées par le nom (dont la fusion avec une ligne locale non verrouillée) et verrouillées après rechargement, ligne non résolue conservée (`unbound` = 1) ; renommage du rôle après le rattachement : aucun LOG « renamed to », toujours verrouillé |

| `standby.sh` | primaire + standby en streaming (`pg_basebackup -R`, second port) : worker actif sur le standby, premier rechargement du standby en échec (`role_state` renommée sur le primaire, `worker_interval = 3600`) retenté en moins de 10 s une fois la table rétablie (revue finale 8), `lock_role` (permanent et temporisé) et verrou automatique du primaire appliqués sur le standby en au plus 2 tours, `unlock_role` du primaire → accepté sur le standby, profil répliqué appliqué aux échecs comptés sur le standby (verrou local qui survit au rechargement, levé par `shmem_unlock_role()`), hash du standby (`max_tracked_roles = 16`) plein de verrous expirés non audités : le rôle suivant est compté et verrouillé (éviction journalisée), rôle supprimé sur le primaire alors qu'un verrou local du standby attend son audit : l'entrée n'est pas évincée par un remplissage de noms inexistants et son `role_locked` (`role_dropped`) est écrit après la promotion (vérifications 9 et 15), verrou local (`shmem_lock_role()`) d'un rôle renommé sur le primaire : après deux tours du worker du standby, aucun LOG « renamed to », verrou visible sous le nouveau nom, le rôle renommé reste verrouillé et le rôle recréé sous l'ancien nom se connecte (vérification 15) ; trou 4 : deux échecs en attente sur le standby, `DROP ROLE` + `CREATE ROLE` rejoués : le nouveau rôle se connecte sur le standby avant la promotion, aucun « temporarily locked » (vérification 15), aucun échec de cycle du worker en lecture seule, échecs et verrou local non acquittés sur le standby puis, après `pg_ctl promote`, copiés dans `role_state` et `audit_log` (`role_locked`, `auth_failed`) par le nouveau primaire |
| `expiry.sh` | `max_age = 1 s` : le worker pose `rolvaliduntil = grace_until`, connexion refusée (côté client « password authentication failed », côté serveur « has an expired password »), audit `password_expired`, `v_role_status`/`v_expiring`, connexion avec le mot de passe de `rotate_password`, **absence du mot de passe généré dans le log serveur**, `expire_password` non annulé par le worker, rôle expiré non verrouillé par 6 tentatives avec le bon mot de passe |
| `notify.sh` | NOTIFY dans la même session (déterministe) et dans une autre session (écouteur en `pg_sleep`), charge utile JSON `event`/`role`/`at`/`details`, absence de mot de passe et de vérificateur, absence du mot de passe dans le log serveur, canal personnalisé `notify_channel`, refus `PPP-010` (direct, via `EXECUTE`, via `_set_password`) et ERROR de `check_password()` dans une base sans l'extension : mot de passe absent du log serveur ; (vérification 6) `check_password` (toujours) et `generate_password` (`enforce_database = on`) lèvent `PPP-003` hors de `pg_pass_policy.database`, WARNING pour `generate_password` avec `off` ; (vérification 7) ce WARNING une seule fois par session ; (vérification 8) un drapeau par source : trois `generate_password()` puis deux `ALTER ROLE` → deux WARNING (le hook n'est pas réduit au silence) |
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
version échoue. `docker/Dockerfile.dockerignore` exclut les objets compilés
et les résultats de test.
