# pg_pass_policy

Extension PostgreSQL (C + SQL) de gestion du cycle de vie des mots de passe des
rôles, pour PostgreSQL **14 à 18** :

- **politique de complexité** appliquée à `CREATE ROLE … PASSWORD` et
  `ALTER ROLE … PASSWORD` (hook `check_password_hook`) : longueur, classes de
  caractères, nom du rôle, dictionnaire de mots de passe courants, répétitions ;
- **historique anti-réutilisation** : seuls les vérificateurs SCRAM-SHA-256 sont
  conservés, jamais un mot de passe en clair ;
- **expiration et rotation** : durée de vie, période de grâce, alertes,
  `VALID UNTIL` posé automatiquement par un background worker, rotation avec
  génération de mot de passe, rotation sans coupure par paire de rôles ;
- **verrouillage** après N échecs d'authentification (hook
  `ClientAuthentication_hook` + mémoire partagée), verrouillage manuel ;
- **profils** de politique (modèle de type Oracle) assignables rôle par rôle ;
- **audit** en table, dans le log serveur (`pg_pass_policy: …`) et par `NOTIFY`.

Le contrat technique complet est dans [`docs/SPEC.md`](docs/SPEC.md) ; les
tests sont décrits dans [`docs/TESTING.md`](docs/TESTING.md).

## Prérequis

- PostgreSQL 14, 15, 16, 17 ou 18, avec les en-têtes de développement
  (`pg_config` disponible, paquet `postgresql-server-dev-NN` sur Debian) ;
- la bibliothèque **doit** être chargée par `shared_preload_libraries` : elle
  installe des hooks et réserve de la mémoire partagée au démarrage. Sans cela,
  `CREATE EXTENSION` échoue avec « pg_pass_policy must be loaded via
  shared_preload_libraries » ;
- l'extension n'est installée que dans **une seule base**, désignée par le
  paramètre `pg_pass_policy.database` (défaut `postgres`) : c'est là que le
  worker se connecte et que les changements de mot de passe doivent être faits
  (voir `enforce_database` plus bas) ;
- `password_encryption = 'scram-sha-256'` (défaut depuis PostgreSQL 14) : les
  mots de passe MD5 sont refusés tant que `pg_pass_policy.require_scram = on`.

## Installation

```sh
make                      # PG_CONFIG=/chemin/vers/pg_config si besoin
make install
```

Dans `postgresql.conf` (redémarrage obligatoire : ces deux paramètres sont de
contexte `postmaster`) :

```
shared_preload_libraries = 'pg_pass_policy'
pg_pass_policy.database  = 'postgres'      # base où sera créée l'extension
```

Puis, connecté en superutilisateur **à la base désignée** :

```sql
CREATE EXTENSION pg_pass_policy;
```

Au démarrage, seuls les rôles de `exempt_roles` passent tant que le worker
n'a pas chargé les verrous (les autres connexions par mot de passe, celles
des superutilisateurs comprises, reçoivent `57P03`, voir « Verrouillage et
déverrouillage »). Le worker occupe une place de `max_worker_processes` : si
aucune n'est libre, ou si `pg_pass_policy.database` n'existe pas, il ne
démarre pas ; 10 secondes après le démarrage, les superutilisateurs sont
alors acceptés et le log porte, au plus une fois par minute, le message
`pg_pass_policy: worker has not loaded the lock state yet (worker_pid = 0)`.

Recommandé : `pg_pass_policy.exempt_roles = 'postgres'` (ou votre compte
d'administration), pour ne jamais être bloqué par un profil trop strict.

`CREATE EXTENSION` crée le schéma `pass_policy`, les tables, les fonctions, les
vues, le profil `default`, charge le dictionnaire de mots de passe courants et
crée les deux rôles `NOLOGIN` suivants s'ils n'existent pas :

| rôle | droits |
|---|---|
| `pass_policy_viewer` | lecture des tables et vues (sauf la colonne `password_history.verifier`) |
| `pass_policy_admin` | membre de `pass_policy_viewer` + exécution de toute l'API d'administration |

Un superutilisateur a toujours tous les droits. Les fonctions d'administration
sont `SECURITY DEFINER` et contrôlent `session_user` (pas `current_user`) :
utiliser un rôle membre de `pass_policy_admin` directement, pas `SET ROLE`.

Désinstallation complète : `DROP EXTENSION pg_pass_policy; DROP SCHEMA
pass_policy; DROP ROLE pass_policy_admin, pass_policy_viewer;` (le schéma et
les rôles survivent à `DROP EXTENSION`, voir plus bas).

## Démarrage rapide

Toutes les fonctions sont dans le schéma `pass_policy`.

### Profils

Le profil `default` s'applique à tout rôle sans assignation. Valeurs par
défaut : 12 à 128 caractères, 3 classes sur 4 (au moins 1 minuscule, 1
majuscule, 1 chiffre, 1 spécial), refus du nom du rôle, du dictionnaire et des
mots de passe pré-hachés, 3 caractères identiques consécutifs au plus,
historique de 5 mots de passe sur 365 jours, `max_age` 90 jours, `min_age`
1 jour, grâce 7 jours, alerte 14 jours avant, verrouillage après 5 échecs en
15 minutes pour 30 minutes.

```sql
-- Création d'un profil : les clés jsonb sont les colonnes de pass_policy.profile
SELECT pass_policy.create_profile('applicatif',
         '{"min_length": 24, "min_classes": 4, "max_age": "30 days",
           "min_age": "0", "max_failures": 10}');
SELECT pass_policy.alter_profile('applicatif', '{"lock_duration": null}');  -- déverrouillage manuel seulement
SELECT pass_policy.assign_profile('app_user', 'applicatif');
SELECT * FROM pass_policy.effective_profile('app_user');
SELECT pass_policy.unassign_profile('app_user');
SELECT pass_policy.drop_profile('applicatif');     -- refusé si le profil est encore assigné
```

### Vérifier et générer un mot de passe

```sql
-- NULL si conforme, sinon le motif (code PPP-xxx + texte), sans effet de bord
SELECT pass_policy.check_password('app_user', $1);          -- $1 : paramètre lié (voir « check_password et le log »)
-- Mot de passe aléatoire (pg_strong_random), conforme au profil, sans 0 O 1 l I |
SELECT pass_policy.generate_password();                     -- 24 caractères, profil default
SELECT pass_policy.generate_password(32, 'applicatif');
```

`generate_password` respecte `min_length`/`max_length` du profil :
`generate_password(8)` échoue avec le profil `default` (minimum 12).

### Rotation

```sql
-- Génère un mot de passe, l'applique (ALTER ROLE), pose VALID UNTIL, audite,
-- et le RETOURNE UNE SEULE FOIS : il n'est stocké nulle part.
SELECT pass_policy.rotate_password('app_user');
SELECT pass_policy.rotate_password('app_user', 32);
-- Forcer un changement : VALID UNTIL = maintenant, statut « expired »
SELECT pass_policy.expire_password('app_user');
```

### État des rôles

```sql
SELECT * FROM pass_policy.v_role_status;   -- un rôle LOGIN par ligne
SELECT * FROM pass_policy.v_expiring;      -- status IN (warning, grace, expired)
SELECT * FROM pass_policy.v_locked;
SELECT * FROM pass_policy.v_recent_audit;  -- 1000 derniers événements
SELECT * FROM pass_policy.failed_attempts();  -- compteurs d'échecs en mémoire partagée
SELECT * FROM pass_policy.worker_status();    -- pid, last_run, last_reload, tracked_roles, locks_loaded
```

`v_role_status.status` vaut `ok`, `warning` (expiration dans moins de
`warn_before`), `grace` (expiré, période de grâce en cours), `expired`,
`locked`, `never_expires` (`max_age` NULL) ou `unknown` (aucune date de
changement connue : rôle antérieur à l'extension, ou créé par `CREATE ROLE …
PASSWORD`, tant que `run_maintenance()` n'a pas créé son état ; la
réconciliation prend alors la date du jour comme date de changement).
La dernière colonne, `role_oid`, sert à joindre `pass_policy.role_state` :
après `ALTER ROLE … RENAME`, `role_state.role_name` garde l'ancien nom
jusqu'au passage suivant de la maintenance ou au prochain `lock_role()`,
`unlock_role()` ou `expire_password()` sur ce rôle (`v_locked` joint déjà par
OID).

### Verrouillage et déverrouillage

Après `max_failures` échecs d'authentification dans `failure_window`, le rôle
est verrouillé pour `lock_duration` (NULL = jusqu'à déverrouillage manuel). Un
rôle verrouillé est refusé **même avec le bon mot de passe** : le client reçoit
`FATAL: role "x" is locked by pg_pass_policy`.

Seuls les échecs des méthodes où le client présente un mot de passe ou un
secret sont comptés : `password`, `md5`, `scram-sha-256`, `ldap`, `pam`,
`radius`, `bsd`. Un échec `peer`, `ident`, `cert`, `gss` ou `sspi` n'est pas
compté : sinon un client autorisé à joindre le serveur pourrait verrouiller
n'importe quel rôle par son nom. Les connexions refusées par une ligne
`reject` de `pg_hba.conf` (ou faute de ligne) ne sont pas comptées non plus.
Le refus d'un rôle verrouillé, lui, s'applique quelle que soit la méthode.

**Au démarrage du serveur**, la mémoire partagée est vide : les verrous
enregistrés dans `role_state` (dont les verrous manuels sans fin) n'y sont
réinjectés que par le premier tour du worker, qui commence par là. Pour
qu'aucun rôle verrouillé ne se glisse dans cette fenêtre, les connexions par
mot de passe ou secret (`password`, `md5`, `scram-sha-256`, `ldap`, `pam`,
`radius`, `bsd`) des rôles non exemptés, superutilisateurs compris, sont
refusées tant que l'état n'est pas chargé, bon ou mauvais mot de passe :
`FATAL: pg_pass_policy: lock state not loaded yet, retry` (SQLSTATE `57P03`,
comme « the database system is starting up » : il suffit de réessayer). Ces
tentatives ne modifient pas le compteur d'échecs : ni échec compté, ni
remise à zéro. La fenêtre dure normalement une fraction de seconde. Si le
worker ne peut pas charger l'état (base `pg_pass_policy.database`
inexistante, `max_worker_processes` épuisé, table illisible, verrous de
`role_state` plus nombreux que `max_tracked_roles`), elle reste fermée et le
log l'indique (au plus une ligne par seconde, plus le message `worker_pid =
0` si le worker n'a jamais démarré, ou un WARNING par minute si le schéma
`pass_policy` n'appartient plus à un superutilisateur) ; le worker réessaie
toutes les 5 secondes, y compris sur un standby, et
`pass_policy.worker_status()` montre `locks_loaded` à faux. Le client, lui,
ne reçoit que le `57P03`, sans détail sur l'état interne. Les rôles de
`pg_pass_policy.exempt_roles` et les connexions sans secret (`peer`,
`cert`…) passent toujours : c'est le filet de sécurité de l'administrateur.
Les superutilisateurs ne passent que si le worker est absent (aucun worker
10 secondes après le démarrage : base inexistante, `max_worker_processes`
épuisé), pour qu'une installation dont le worker ne démarre pas reste
administrable ; ils restent alors refusés si un verrou est déjà en mémoire
partagée. Pendant un démarrage normal, un superutilisateur verrouillé dans
`role_state` est donc refusé comme les autres. Avec `enabled = off`, rien
n'est bloqué ; avec `worker_interval = 0`, le worker fait quand même ce
premier chargement au démarrage.

```sql
SELECT pass_policy.lock_role('app_user');                              -- manuel, sans fin : renvoie infinity
SELECT pass_policy.lock_role('app_user', interval '1 hour', 'incident');  -- renvoie la fin du verrou
SELECT pass_policy.unlock_role('app_user');                            -- remet aussi le compteur à zéro
```

`lock_duration` et `failure_window` (sauf 0, « pas de fenêtre ») valent au
moins une seconde : la mémoire partagée les reçoit en secondes entières.
Un verrou automatique levé par `unlock_role()` avant le passage du worker est
tout de même journalisé (`role_locked`, `details.lifted_before_audit = true`),
sans être recopié dans `role_state` ; s'il est remplacé par un `lock_role()`,
sa ligne porte `details.replaced_by_manual = true`. À l'inverse, un nouveau verrou automatique
posé juste avant ou pendant un `unlock_role()` ou un `run_maintenance()` (qui
lève les verrous expirés) n'est pas levé par eux, et un verrou automatique
expiré avant le passage du worker est journalisé normalement (sans
`lifted_before_audit`), même si un `run_maintenance()` passe entre-temps. Les échecs sur des noms de
rôles inexistants sont journalisés en une seule ligne `auth_failed` par tour
du worker (`role_name` NULL, `details.unknown_roles` et `details.attempts`).
Si la bibliothèque a été retirée de
`shared_preload_libraries` après l'installation, `lock_role()` et
`unlock_role()` échouent (ERROR) au lieu de valider `role_state` sans effet sur
l'authentification.

### Rotation sans coupure (paires de rôles)

Deux rôles physiques, membres (`INHERIT`) d'un rôle de groupe qui porte les
privilèges, alternent : l'application se reconnecte avec le nouveau couple
(rôle, mot de passe) pendant que l'ancien reste valable le temps de la période
de grâce du profil.

```sql
-- crée les rôles manquants (LOGIN, membres du groupe) ; le groupe doit exister
SELECT pass_policy.create_rotation_pair('app', 'app_a', 'app_b', 'app_group');
-- génère un mot de passe pour le rôle inactif, le rend actif, borne l'ancien
SELECT active_role, password, previous_role, previous_valid_until
  FROM pass_policy.switch_rotation_pair('app');
```

### Maintenance

Le background worker exécute `pass_policy.run_maintenance()` toutes les
`pg_pass_policy.worker_interval` secondes : synchronisation de `VALID UNTIL`,
alertes `expiry_warning`, événements `password_expired`, déverrouillages
automatiques, purge des rôles supprimés, réconciliation de
`pg_authid.rolpassword` avec l'historique, rechargement des paramètres de
verrouillage en mémoire partagée. La fonction est aussi appelable à la main (ou
par pg_cron) et renvoie les actions effectuées ; deux passes simultanées
(worker et pg_cron par exemple) s'attendent (verrou consultatif de
transaction). Avec `worker_interval = 0`, le
worker ne fait plus que la synchronisation de la mémoire partagée : il faut
appeler `run_maintenance()` soi-même.

Autres fonctions : `purge_audit(interval DEFAULT '365 days')`,
`load_dictionary(text[])`, `audit(event_type, role_name, details jsonb)`
(réservée à `pass_policy_admin`). `rebind_restored_roles()` (superutilisateur
seulement) rattache par nom les lignes d'un rôle après une restauration dans
un autre cluster (voir « Avertissements de sécurité »). Aucune fonction ni le schéma ne sont
accordés à `PUBLIC` : un utilisateur ordinaire change son propre mot de passe
par `ALTER ROLE … PASSWORD`, les requêtes internes du hook s'exécutant avec
les droits du superutilisateur.

## Paramètres (GUC)

Tous préfixés `pg_pass_policy.`. Contexte `postmaster` = redémarrage ;
`SIGHUP` = `ALTER SYSTEM SET …` ou `postgresql.conf` puis
`SELECT pg_reload_conf()` (`SET` est refusé).

| paramètre | type | défaut | contexte | rôle |
|---|---|---|---|---|
| `enabled` | bool | `on` | SIGHUP | `off` : les hooks ne font rien et le worker est suspendu (ni maintenance, ni audit, ni `role_state`, ni rechargement de la mémoire partagée) ; les échecs et verrous déjà comptés restent en attente en mémoire partagée et sont journalisés au retour à `on` |
| `database` | string | `postgres` | postmaster | base où l'extension est installée et où le worker se connecte |
| `worker_interval` | int (s) | `60` | SIGHUP | `0` : pas de tour périodique (appeler `run_maintenance()` à la main) ; le worker charge quand même les verrous au démarrage |
| `max_tracked_roles` | int | `1024` | postmaster | taille du hash de verrouillage en mémoire partagée (16 à 1 048 576). Doit dépasser le nombre de rôles LOGIN qui ont un profil ou un verrou : ces entrées ne sont jamais évincées ; si le hash n'en contient plus d'autres, les échecs ne sont plus comptés (LOG « cannot track ») et `lock_role()` échoue (ERROR 53400, transaction annulée). Les entrées des noms de rôles inexistants et les compteurs inactifs sont évincés en premier. Recommandation : une valeur largement supérieure au nombre de rôles, avec une marge (voir « Énumération des rôles ») |
| `manage_valid_until` | bool | `on` | SIGHUP | le worker écrit `pg_authid.rolvaliduntil` |
| `log_events` | bool | `on` | SIGHUP | une ligne `LOG: pg_pass_policy: …` par événement |
| `notify_channel` | string | `pg_pass_policy` | SIGHUP | canal `NOTIFY` (charge utile JSON `event`/`role`/`at`/`details`) |
| `exempt_roles` | liste | `''` | SIGHUP | rôles exemptés de la politique **et** du verrouillage, séparés par des virgules, règles des identifiants SQL : noms non cités mis en minuscules, noms entre guillemets conservés tels quels (`'postgres, "App User"'`). `rotate_password()`, `switch_rotation_pair()` et `run_maintenance()` ne posent pas de `VALID UNTIL` sur un rôle exempté : ils relèvent seulement une borne déjà passée (pour `run_maintenance()` : une borne posée par l'extension, `expire_password()` par exemple, une fois le mot de passe changé) |
| `superuser_bypass` | bool | `off` | SIGHUP | `on` : les superutilisateurs échappent à la complexité (pas à l'historique) |
| `require_scram` | bool | `on` | SIGHUP | refuse les mots de passe MD5 (`PPP-002`) |
| `enforce_database` | bool | `on` | SIGHUP | hors de `database`, `ALTER ROLE … PASSWORD` est refusé (`PPP-003`) ; `off` : accepté sans contrôle avec un `WARNING` |

## Codes de refus `PPP-xxx`

Un refus par le hook est une erreur SQLSTATE `28P01` (`invalid_password`) dont
le message commence par le code ; `check_password()` renvoie le même code en
texte. Le mot de passe n'apparaît jamais dans le message, le log ni l'audit.
Un refus n'écrit pas de ligne dans `audit_log` (l'erreur annule la
transaction) : la trace est une ligne du log serveur,
`pg_pass_policy: password_rejected role=<rôle> {"code": "PPP-0xx"}`, si
`pg_pass_policy.log_events = on`.

| code | motif |
|---|---|
| `PPP-001` | mot de passe pré-haché (MD5 ou SCRAM) refusé : la politique ne peut pas être vérifiée (`reject_prehashed`) |
| `PPP-002` | mot de passe MD5 refusé (`require_scram = on`) |
| `PPP-003` | changement de mot de passe hors de la base `pg_pass_policy.database` (`enforce_database = on`) |
| `PPP-004` | l'extension est installée mais son schéma `pass_policy` n'est pas fiable (propriétaire non superutilisateur) : tout changement de mot de passe est refusé (SQLSTATE `55000`) |
| `PPP-010` | trop court (`min_length`) |
| `PPP-011` | trop long (`max_length`) |
| `PPP-012` | pas assez de classes de caractères (`min_classes`) |
| `PPP-013` | pas assez de minuscules (`min_lower`) |
| `PPP-014` | pas assez de majuscules (`min_upper`) |
| `PPP-015` | pas assez de chiffres (`min_digit`) |
| `PPP-016` | pas assez de caractères spéciaux (`min_special`) |
| `PPP-017` | contient le nom du rôle, quelle que soit la casse, même inversé (`reject_username`) |
| `PPP-018` | présent dans le dictionnaire des mots de passe courants (`reject_dictionary`) |
| `PPP-019` | trop de caractères identiques consécutifs (`max_repeat`) |
| `PPP-020` | caractère de contrôle, ou espace en début ou en fin |
| `PPP-030` | changé trop récemment (`min_age` ; non appliqué à un superutilisateur) |
| `PPP-031` | parmi les `history_count` derniers mots de passe, l'actuel compris (`history_days`) |

Les caractères sont comptés en points de code UTF-8 ; tout caractère non ASCII
compte comme « spécial ».

## Avertissements de sécurité

- **Énumération des rôles** : un nom inexistant est « verrouillé » comme un
  vrai rôle, pour que la réponse ne révèle pas son existence. Mais l'entrée
  d'un nom inexistant reste évincable (sinon un flot de noms inventés
  remplirait la mémoire partagée) : un attaquant qui, après le verrou, sature
  le hash avec environ `max_tracked_roles` autres noms inexistants voit le
  pseudo-verrou disparaître, alors que le verrou d'un vrai rôle reste.
  L'oracle est donc atténué, pas éliminé : il exige de saturer le hash.
  Dimensionner `max_tracked_roles` largement au-dessus du nombre de rôles,
  avec une marge, et surveiller les lignes `auth_failed` agrégées
  (`details.unknown_roles`).
- **`enforce_database = off`, `enabled = off` ou rôle exempté** : un
  changement de mot de passe fait hors du hook (hors de
  `pg_pass_policy.database` avec `enforce_database = off`, hook désactivé, ou
  rôle de `exempt_roles`) est normalement détecté par `run_maintenance()` (ligne
  `password_changed`, `details.source = reconciliation`). Exception : s'il
  survient entre un changement passé par le hook et la passe suivante de
  `run_maintenance()`, il est pris pour l'écart de sel attendu entre le
  vérificateur calculé par le hook et celui que PostgreSQL stocke : l'historique
  reçoit le nouveau vérificateur sans ligne d'audit ni remise à zéro de la date
  de changement. Avec `enforce_database = on` et `enabled = on` (défauts),
  ce cas ne peut se produire que pour un rôle exempté.

- **Mots de passe pré-hachés** : avec `reject_prehashed = true` (défaut), la
  commande `\password` de psql (qui envoie un vérificateur SCRAM) et la
  restauration d'un `pg_dumpall` (`ALTER ROLE … PASSWORD 'SCRAM-SHA-256$…'`)
  sont refusées avec `PPP-001`. Le temps d'une restauration, passer
  `pg_pass_policy.enabled = off` (`ALTER SYSTEM` + `pg_reload_conf()`), puis le
  remettre à `on` : le `run_maintenance()` suivant réconcilie l'historique avec
  `pg_authid.rolpassword` et prend la date de la restauration comme date de
  changement des rôles restaurés (le compte à rebours de `max_age` repart de là).
- **Restauration dans un autre cluster** : les OID des rôles changent, et
  l'ancien OID d'un rôle peut appartenir à un autre. `run_maintenance()` suit
  les OID (dans un cluster vivant, un OID existant sous un autre nom est un
  renommage) : laissé seul, il réétiquetterait les verrous, profils et
  historiques d'un rôle au nom de celui qui a hérité de son OID. Procédure :
  1. `pg_pass_policy.enabled = off` (`ALTER SYSTEM` + `pg_reload_conf()`) :
     ni contrôle des mots de passe pré-hachés, ni tour du worker pendant la
     restauration (le worker est suspendu : ni `run_maintenance()`, ni
     écriture d'audit ou de `role_state`, ni rechargement) ; suspendre aussi
     tout `run_maintenance()` planifié par ailleurs (pg_cron) ;
  2. restaurer les rôles (`pg_dumpall --roles-only`) puis la base
     (`pg_restore`) ;
  3. en superutilisateur, `SELECT * FROM pass_policy.rebind_restored_roles();`
     **avant** le premier `run_maintenance()` : chaque ligne de `role_state`,
     `role_profile` et `password_history` dont le couple (OID, nom) ne
     correspond à aucun rôle est rattachée au rôle de ce nom (`rebind`), ou
     supprimée si aucun rôle ne porte ce nom (`purge`) ; une ligne
     `maintenance` est écrite dans l'audit ;
  4. remettre `enabled` à `on` (et réactiver la planification éventuelle) :
     le premier tour du worker recharge la mémoire partagée depuis les
     tables restaurées.
- **Superutilisateur** : un superutilisateur peut être verrouillé comme n'importe
  quel rôle, et les profils (`default` compris) s'appliquent à lui : un membre
  de `pass_policy_admin` non superutilisateur ne peut pas le viser avec
  `rotate_password`, `expire_password`, `lock_role`… (ni un rôle membre d'un
  superutilisateur, d'un rôle `pg_*` ou, sur PostgreSQL ≤ 15, d'un rôle
  `CREATEROLE`), ni lui assigner ou retirer un profil. En revanche il peut
  modifier le profil `default`, que `run_maintenance()` applique ensuite à tous
  les rôles sans profil, superutilisateurs compris (expiration, `VALID UNTIL`,
  verrouillage). Pour ne pas se retrouver dehors après quelques
  fautes de frappe ou un profil trop strict, mettre
  `pg_pass_policy.exempt_roles = 'postgres'` (ou le nom de votre compte
  d'administration).
- **`check_password` et le log** : le mot de passe candidat est un argument de
  requête, l'extension ne peut pas empêcher le serveur de journaliser cette
  requête. Un paramètre lié (`$1`, `PREPARE`, API cliente, c'est ce que fait
  `pgpp check`) évite le littéral dans `pg_stat_activity.query` et l'historique
  de psql, mais **pas** dans le log serveur : depuis PG 13,
  `log_parameter_max_length` vaut -1 par défaut et `log_statement = all` comme
  `log_min_duration_statement` écrivent `DETAIL: parameters: $1 = '…'`. Pour
  les rôles qui appellent `check_password` (la fonction n'est pas accordée à
  PUBLIC), un superutilisateur pose donc : `ALTER ROLE <appelant> SET
  log_parameter_max_length = 0`, `SET log_statement = 'none'` et `SET
  log_min_duration_statement = -1` (ces trois GUC ne sont pas modifiables par
  une session ordinaire ; à partir de PG 15, `GRANT SET ON PARAMETER
  log_parameter_max_length TO <appelant>` permet à `pgpp check` de poser
  lui-même `SET LOCAL log_parameter_max_length = 0` ; `log_parameter_max_length_on_error` reste à 0, sa
  valeur par défaut, pour ne rien journaliser non plus en cas d'erreur ;
  penser aussi à `auto_explain.log_parameter_max_length` si auto_explain est
  chargé). Un wrapper `SECURITY DEFINER … SET log_parameter_max_length = 0`
  ne protège pas : le SET d'une fonction est restauré avant la journalisation
  de la requête englobante. `pg_stat_statements` normalise les constantes
  (`$1`, `$2`) et n'expose pas le mot de passe. L'extension masque le texte de
  la commande (`STATEMENT`, `CONTEXT`) dans ses propres messages, mais un
  `ALTER ROLE … PASSWORD 'clair'` tapé par un utilisateur reste soumis à
  `log_statement` : préférer `rotate_password()`.
- **auto_explain** : avec `auto_explain.log_nested_statements = on`, les
  requêtes internes de l'extension seraient journalisées avec leurs paramètres
  (vérificateur SCRAM du nouveau mot de passe). L'extension met
  `auto_explain.log_min_duration = -1` le temps de ses propres requêtes (hook,
  `rotate_password`, `switch_rotation_pair`, `run_maintenance`) ; ces appels
  n'apparaissent donc pas dans les plans d'auto_explain.
- **`manage_valid_until = off`** : le worker ne touche plus à `VALID UNTIL`,
  sauf pour relever (à `infinity`) une borne passée qu'il a lui-même posée
  (`expire_password`, ancienne synchronisation) une fois le mot de passe
  changé ; sans cela le rôle resterait bloqué indéfiniment après un
  `ALTER ROLE … PASSWORD` classique. `rotate_password()` et
  `switch_rotation_pair()` ne posent alors pas non plus de `VALID UNTIL` sur
  le rôle dont le mot de passe change.
- **Propriétaire du schéma** : le schéma `pass_policy` doit appartenir à un
  superutilisateur (celui qui a fait `CREATE EXTENSION`). S'il est cédé à un
  autre rôle (`ALTER SCHEMA … OWNER TO`) ou si son propriétaire perd l'attribut
  `SUPERUSER`, le hook refuse tout changement de mot de passe avec `PPP-004`
  plutôt que d'accepter sans politique.
- **Base du worker** : `pg_pass_policy.database` doit exister au démarrage ;
  sinon le worker échoue avec le FATAL standard « database "x" does not
  exist » et le postmaster le relance toutes les 10 secondes (une ligne par
  tentative dans le log). Le GUC est de contexte `postmaster` : corriger la
  valeur puis redémarrer.
- **Mot de passe retourné une seule fois** : `rotate_password()` et
  `switch_rotation_pair()` génèrent le mot de passe côté serveur et le
  renvoient dans le résultat ; il n'est ni stocké ni journalisé ni envoyé par
  `NOTIFY`. S'il est perdu, relancer une rotation.
- **Expiration côté client** : un rôle dont le mot de passe a expiré reçoit
  seulement « password authentication failed » ; la cause (« has an expired
  password ») n'apparaît que dans le log serveur.
- **`DROP EXTENSION`** laisse le schéma `pass_policy` (vide) et les rôles
  `pass_policy_admin` / `pass_policy_viewer` en place : le schéma est déclaré
  par la clé `schema` du fichier `.control` et n'appartient pas à l'extension,
  les rôles sont des objets globaux. Les supprimer à la main si besoin.
- **Historique** : `password_history.verifier` contient les vérificateurs SCRAM
  (matière à attaque hors ligne) ; la colonne n'est lisible que par le
  propriétaire de l'extension, pas par `pass_policy_viewer`.

## Tests

```sh
make test                    # make install + pg_regress sur instance temporaire + tests shell
make install && make installcheck      # pg_regress seul (12 fichiers, instance jetable)
bash test/shell/run-all.sh             # verrouillage, expiration, NOTIFY avec de vraies connexions
```

`make check` n'est pas pris en charge par PGXS. Chaque test démarre et arrête
sa propre instance : aucune instance de développement n'est touchée. Détails,
conventions et régénération des fichiers attendus : [`docs/TESTING.md`](docs/TESTING.md).

Matrice PostgreSQL 14 → 18 avec Docker :

```sh
docker compose -f docker/compose.yml build pg17
docker compose -f docker/compose.yml run --rm pg17
docker/run-all.sh            # toutes les versions, récapitulatif PASS/FAIL (-j : en parallèle)
```

## Arborescence

```
sql/pg_pass_policy--1.0.sql   schéma pass_policy : tables, fonctions, vues, droits
src/                          pg_pass_policy.c (GUC, shmem, worker), policy.c (hook mot de passe),
                              lockout.c (hook d'authentification), worker.c, compat.h
test/sql, test/expected       pg_regress
test/shell                    tests avec vraies connexions
docker/                       matrice 14 → 18
docs/                         SPEC.md (contrat), TESTING.md
cli/, web/                    CLI et back-office prévus (répertoires vides pour l'instant)
```

## Licence

Licence PostgreSQL (voir [`LICENSE`](LICENSE)). Copyright (c) 2026, Robin Portigliatti.
