# pgpp-web — back-office web de pg_pass_policy

Interface d'administration de l'extension PostgreSQL `pg_pass_policy`
(FastAPI + Jinja2 + HTMX, psycopg 3). Elle ne fait rien d'autre que ce que
l'API SQL du schéma `pass_policy` autorise : toutes les actions passent par les
fonctions `pass_policy.*` (`rotate_password`, `lock_role`, `unlock_role`,
`expire_password`, `create_profile`, `alter_profile`, `drop_profile`,
`assign_profile`, `unassign_profile`, `create_rotation_pair`,
`switch_rotation_pair`, `run_maintenance`) et par les vues (`v_role_status`,
`v_expiring`, `v_recent_audit`). Aucun `ALTER ROLE` n'est émis directement.

Pages :

| URL | contenu |
|---|---|
| `/` | tableau de bord : compteurs par statut (`v_role_status`), rôles en expiration (`v_expiring`), état du worker (`worker_status()`), derniers événements (`v_recent_audit`) |
| `/roles` | tableau filtrable (statut, profil, recherche) ; actions rotate / lock / unlock / expire avec confirmation ; la rotation affiche le mot de passe **une seule fois** avec un bouton « Copy » |
| `/profiles` | liste, création, modification, suppression, assignation aux rôles |
| `/audit` | journal d'audit avec filtres (rôle, type, depuis) et pagination (voir ci-dessous) |
| `/pairs` | paires de rotation : liste, création, bascule avec affichage unique du mot de passe |
| `/maintenance` | exécution manuelle de `run_maintenance()` |
| `/healthz` | sonde de vie (sans authentification, ne touche pas la base) |

Audit : le filtre « depuis » accepte une date (`2026-10-27`,
`2026-10-27T10:00`, ou la forme ISO compacte `20261027`) ou une durée avec
son unité (`7 days`, `12 hours`). Une valeur qui ressemble à une date sans
en être une (`2026-13-45`) est refusée (« invalid date »), de même qu'un
nombre seul qui n'est pas une date valide (`7`, `20261345`), que PostgreSQL
lirait comme des secondes : l'unité est exigée. La pagination lit une ligne
de plus que la page pour savoir s'il existe une page suivante, sans compter
toute la sélection à chaque page (pas de `count(*) OVER ()`). La page et le
total viennent d'une seule requête, donc du même instantané : ils ne peuvent
pas se contredire. Sur une page incomplète (la dernière), le total se déduit
de la page elle-même, sans comptage. Sinon, le total est un comptage borné
qui s'arrête à 10 001 lignes, exécuté dans la même requête seulement quand
il est nécessaire : exact jusqu'à 10 000 événements, il s'affiche
« 10,000+ » au-delà, sur toutes les pages (la dernière comprise), sans
nombre de pages (lien « next » seul). Une page au-delà de la fin (lien
périmé) ramène à la vraie dernière page sous le plafond. Au-delà du plafond,
la dernière page n'est pas connue (jamais de comptage exact non borné) : la
page demandée s'affiche vide, avec un message qui le dit et un lien vers la
première page.

Statut et état du mot de passe : la colonne `status` de `v_role_status`
montre d'abord le verrou (`locked`) puis l'exemption (`exempt`) ; l'état du
mot de passe seul (`expiry_state` : `ok`, `warning`, `grace`, `expired`,
`never_expires`, `unknown`) est affiché à part, sous le statut, quand il en
diffère (rôle verrouillé dont le mot de passe a expiré, par exemple). Pour
un rôle exempté (`pg_pass_policy.exempt_roles`), l'expiration n'est pas
appliquée : cet état est grisé, le badge « must change », les jours
restants et le bouton « Expire » ne sont pas affichés, et le rôle
n'apparaît jamais dans la liste « Expiring or expired » du tableau de bord.

## Installation

Prérequis : Python ≥ 3.11, FastAPI ≥ 0.118 (dépendances déclarées avec
`Depends(..., scope="function")`), une base où `pg_pass_policy` est installée
(`shared_preload_libraries`, `CREATE EXTENSION pg_pass_policy`).

```sh
cd web
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'      # ou `pip install .` sans les outils de test
```

HTMX est servi localement depuis `app/static/htmx.min.js` (version 2.0.4) :
aucun CDN n'est nécessaire et la CSP n'autorise que l'origine de l'application.

### Rôle PostgreSQL dédié

L'application se connecte avec un rôle de service, membre de
`pass_policy_admin`, qui n'a besoin d'aucun autre privilège :

```sql
CREATE ROLE pgpp_web LOGIN IN ROLE pass_policy_admin;
SELECT pass_policy.rotate_password('pgpp_web');   -- le mot de passe est affiché une fois
```

Le mot de passe se range dans un fichier `~/.pgpass` (mode 0600) ou se passe
par `PGPASSWORD` dans l'environnement du service, jamais dans l'URL de
connexion. Un membre de `pass_policy_admin` qui n'est pas superutilisateur ne
peut pas agir sur les rôles privilégiés (`SUPERUSER`, `REPLICATION`,
`BYPASSRLS`, rôles prédéfinis `pg_*`, membres même indirects de tels rôles) :
c'est voulu par l'extension. L'application détermine une seule fois, à la
première requête, si son rôle de service est superutilisateur : après un
changement de ses attributs, redémarrer l'application.

## Configuration

Tout passe par des variables d'environnement préfixées `PGPP_WEB_`.

| variable | défaut | rôle |
|---|---|---|
| `PGPP_WEB_DATABASE_URL` | *(vide)* | chaîne de connexion libpq (`postgresql://pgpp_web@hôte:5432/postgres`). Vide : les variables `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSFILE`… de libpq s'appliquent |
| `PGPP_WEB_SECRET` | **obligatoire** | clé de signature du cookie de session (jeton CSRF), 32 caractères minimum : `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` |
| `PGPP_WEB_AUTH` | `basic` | `basic` (HTTP basic) ou `proxy` (en-tête posé par un reverse proxy) |
| `PGPP_WEB_BASIC_USERS` | *(vide)* | mode `basic` : `user:hash-bcrypt,user2:hash-bcrypt`, toutes les empreintes du même coût bcrypt ; un utilisateur cité deux fois empêche le démarrage |
| `PGPP_WEB_PROXY_HEADER` | `X-Remote-User` | mode `proxy` : en-tête portant l'utilisateur authentifié (`REMOTE_USER` est accepté et correspond à `Remote-User`) |
| `PGPP_WEB_PROXY_HEADER_ENCODING` | `utf-8` | mode `proxy` : encodage de la valeur de l'en-tête, `utf-8` ou `latin-1` (voir « Reverse proxy ») |
| `PGPP_WEB_TRUSTED_PROXIES` | `127.0.0.1,::1` | mode `proxy` : adresses ou réseaux (CIDR) autorisés à poser l'en-tête ; `unix` pour un socket Unix ; `*` pour tout accepter (déconseillé) |
| `PGPP_WEB_SESSION_HTTPS_ONLY` | `false` | marque le cookie de session `Secure` et le nomme `__Host-pgpp_session` : **obligatoire derrière HTTPS** (voir Sécurité) |
| `PGPP_WEB_REALM` | `pg_pass_policy` | realm HTTP basic |
| `PGPP_WEB_POOL_MIN` / `PGPP_WEB_POOL_MAX` | `1` / `4` | taille du pool de connexions (chaque connexion est vérifiée à sa sortie du pool et remplacée si le serveur l'a fermée) ; `POOL_MIN` ≥ 0, `POOL_MAX` ≥ 1 et `POOL_MAX` ≥ `POOL_MIN`, sinon l'application refuse de démarrer |
| `PGPP_WEB_POOL_TIMEOUT` | `10` | attente maximale (s) d'une connexion du pool, nombre strictement positif et fini (refus au démarrage sinon) |
| `PGPP_WEB_PAGE_SIZE` | `50` | taille de page de l'audit |
| `PGPP_WEB_APP_NAME` | `pgpp-web` | préfixe de l'`application_name` PostgreSQL |

### Comptes HTTP basic

Les mots de passe ne sont stockés qu'en empreinte bcrypt, limitée à 72 octets
en UTF-8 : `pgpp-web-hash` refuse un mot de passe plus long (bcrypt ignorerait
la suite) et l'authentification le refuse de même au lieu de le tronquer. La
commande
`pgpp-web-hash` lit le mot de passe au clavier (sans écho) et affiche l'entrée
à placer dans `PGPP_WEB_BASIC_USERS` :

```sh
pgpp-web-hash alice
# Password: ...
# alice:$2b$12$...
export PGPP_WEB_BASIC_USERS='alice:$2b$12$...,bob:$2b$12$...'
```

Une empreinte tronquée ou abîmée (coupée par le shell, une apostrophe, un
retour à la ligne) est refusée au démarrage : une empreinte bcrypt compte
60 caractères, `$2b$NN$` puis 53 caractères de `[./A-Za-z0-9]`.

Le navigateur renvoie le même en-tête `Authorization` à chaque requête : pour
ne pas payer la vérification bcrypt (coûteuse par construction) à chaque
fois, une vérification réussie est mémorisée dans la session. Celle-ci ne
garde qu'une empreinte HMAC-SHA256, calculée avec `PGPP_WEB_SECRET`, de
l'en-tête et de l'empreinte bcrypt configurée, jamais l'en-tête ni le mot de
passe (le cookie de session est signé, pas chiffré). Un autre en-tête (autre
utilisateur, autre mot de passe), une empreinte modifiée dans
`PGPP_WEB_BASIC_USERS` (mot de passe changé, utilisateur retiré) ou un
changement de `PGPP_WEB_SECRET` invalident ce cache : bcrypt est alors
rejoué. Un échec efface le cache.

Nom d'utilisateur (HTTP basic ou en-tête du proxy) : 1 à 128 caractères,
sans caractère de contrôle C0 ou C1 (U+0000 à U+001F, U+007F à U+009F) ni
séparateur de ligne ou de paragraphe (U+2028, U+2029), qu'un journal ou un
terminal afficherait comme un saut de ligne.

Le nom de l'utilisateur web est enregistré dans `pass_policy.audit_log`
(colonne `application_name`, valeur `pgpp-web:alice`) : chaque action reste
attribuable à une personne même si tous passent par le même rôle PostgreSQL.
PostgreSQL limite `application_name` à 63 octets et y remplace tout octet non
ASCII par `?` : le nom est donc encodé en pourcentage (`Émilie` devient
`pgpp-web:%C3%89milie`, `%` lui-même devient `%25`) puis raccourci, sans
jamais couper une séquence d'échappement, pour tenir en 63 octets avec le
préfixe.

## Lancement

```sh
export PGPP_WEB_DATABASE_URL='postgresql://pgpp_web@127.0.0.1:5432/postgres'
export PGPASSFILE=/etc/pgpp-web/pgpass            # mot de passe du rôle pgpp_web
export PGPP_WEB_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export PGPP_WEB_BASIC_USERS='alice:$2b$12$...'
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
```

L'application est une *factory* (`create_app`) : l'option `--factory` est
nécessaire. Sur un socket Unix : `--uds /run/pgpp-web.sock`.

## Reverse proxy

En production, l'application s'écoute sur `127.0.0.1` ou un socket Unix et un
reverse proxy (nginx, Apache, Caddy…) termine le TLS. Deux options :

1. **HTTP basic géré par l'application** (`PGPP_WEB_AUTH=basic`) : le proxy
   transmet simplement l'en-tête `Authorization`.
2. **Authentification déléguée au proxy** (`PGPP_WEB_AUTH=proxy`) : le proxy
   authentifie (LDAP, OIDC, certificats clients…) et transmet l'identité dans
   `X-Remote-User`. L'application n'accepte cet en-tête que si l'adresse du pair
   figure dans `PGPP_WEB_TRUSTED_PROXIES` ; le proxy **doit** écraser tout
   `X-Remote-User` envoyé par le client. Une adresse IPv4 vue sous sa forme
   IPv6 (`::ffff:127.0.0.1`, uvicorn lancé avec `--host ::`) est comparée sous
   ses deux formes.

Exemple nginx (option 2) :

```nginx
location / {
    auth_basic           "pg_pass_policy";
    auth_basic_user_file /etc/nginx/pgpp.htpasswd;
    proxy_pass           http://127.0.0.1:8000;
    proxy_set_header     X-Remote-User $remote_user;   # écrase la valeur du client
    proxy_set_header     Authorization "";
    proxy_set_header     Host $host;
    proxy_set_header     X-Forwarded-Proto $scheme;
}
```

Point d'attention : la vérification du pair de confiance utilise l'adresse de
la connexion TCP. Si uvicorn est lancé avec `--proxy-headers` et
`--forwarded-allow-ips` incluant le proxy, l'adresse vue par l'application
devient celle du client final (`X-Forwarded-For`) et la vérification échoue :
lancer uvicorn avec `--no-proxy-headers` en mode `proxy`, ou ajouter les
réseaux des clients à `PGPP_WEB_TRUSTED_PROXIES` en connaissance de cause.
Les liens générés sont relatifs (chemin seul) : un préfixe de chemin se
déclare avec `--root-path /pgpp`.

En mode `proxy`, la valeur de l'en-tête est décodée dans l'encodage fixé par
`PGPP_WEB_PROXY_HEADER_ENCODING` : `utf-8` par défaut (`Émilie` arrive sous
la forme des octets `C3 89 6D…`), ou `latin-1` pour un mandataire qui envoie
du latin-1 (`É` est alors l'octet `C9`). Le décodage est strict : une valeur
qui n'est pas valide dans cet encodage est refusée (401, `proxy header not
valid utf-8`), jamais relue dans un autre encodage. Un nom donné provient
ainsi d'une seule suite d'octets. Changement de comportement pour les noms
non ASCII : auparavant, la valeur était toujours lue en latin-1 et un nom
envoyé en UTF-8 arrivait déformé (`Émilie` devenait `Ã\x89milie`) ; avec
l'encodage par défaut, le nom réel est désormais lu, ce qui change le nom
enregistré dans `application_name` et donc dans le journal d'audit. Un
mandataire qui envoie du latin-1 doit déclarer
`PGPP_WEB_PROXY_HEADER_ENCODING=latin-1`.

Derrière HTTPS, `PGPP_WEB_SESSION_HTTPS_ONLY=true` est requis : le cookie de
session devient `__Host-pgpp_session` (`Secure`, `Path=/`, sans `Domain`),
qu'aucune autre origine du même site (autre sous-domaine, autre port, réponse
en HTTP clair) ne peut écraser.

Limitation de débit : l'application ne freine pas elle-même les tentatives
HTTP basic (bcrypt, coût 12 avec `pgpp-web-hash`, ralentit chaque essai, mais rien n'arrête un
dictionnaire patient). Chaque échec est journalisé en `WARNING` avec le nom
d'utilisateur et l'adresse du pair (`basic authentication failed for user
alice from 10.0.0.9`), jamais le mot de passe. Le reverse proxy doit limiter
le débit sur `/` et, idéalement, bannir les sources qui accumulent les 401 :

```nginx
limit_req_zone $binary_remote_addr zone=pgpp:1m rate=5r/s;
location / {
    limit_req zone=pgpp burst=20 nodelay;
    ...
}
```

Avec fail2ban, un filtre sur les lignes `basic authentication failed for user
… from <ip>` du journal d'uvicorn (ou sur les 401 du journal d'accès du proxy)
complète le dispositif. Un verrouillage par compte dans l'application a été
écarté : derrière le proxy l'adresse vue est celle du proxy, et un compteur
par utilisateur serait un déni de service trivial sur l'unique compte admin.

## Sécurité

- **Mots de passe** : générés côté serveur par l'extension, renvoyés une seule
  fois dans le fragment HTML de la réponse (`Cache-Control: no-store`), jamais
  placés dans une URL, un cookie, la session, un log ni l'audit. Le fragment
  propose « Copy » et « Hide » ; HTMX est configuré sans cache d'historique
  (`historyCacheSize: 0`, `hx-history="false"`) pour qu'aucun instantané du DOM
  n'atterrisse dans `localStorage`.
- **SQL** : toutes les valeurs sont des paramètres liés (psycopg 3) ; aucune
  concaténation de valeur dans le texte SQL ; aucune commande DDL directe.
- **CSRF** : jeton par session dans un cookie signé (`itsdangerous`, secret
  `PGPP_WEB_SECRET`, `HttpOnly`, `SameSite=Strict`, préfixe `__Host-` avec
  `PGPP_WEB_SESSION_HTTPS_ONLY`), vérifié sur toute requête non sûre (POST…),
  transmis par HTMX dans l'en-tête `X-CSRF-Token` (`hx-headers` sur `<body>`)
  ou par le champ `csrf_token` des formulaires classiques. Le jeton est **lié à
  l'utilisateur authentifié** (nom enregistré dans la session) et régénéré dès
  que l'identité derrière le cookie change : une session plantée par un tiers
  (*cookie tossing*) ne sert à rien avec les identifiants que le navigateur
  envoie de lui-même (HTTP basic, en-tête du proxy). Aucun jeton ni cookie
  n'est émis sur les pages 401/403 affichées avant l'authentification. Une
  requête marquée `Sec-Fetch-Site: cross-site` ou `same-site` est refusée : le
  back-office n'a pas d'appelant légitime sur un autre sous-domaine ou port.
  Un refus CSRF suit trois règles. Un jeton fourni mais périmé (page restée
  ouverte pendant que la session expirait ou était renouvelée :
  `PGPP_WEB_SECRET` changé, autre identité) donne, pour une requête htmx,
  une réponse portant `HX-Refresh: true` : la page est rechargée
  automatiquement avec un jeton neuf. Pour un formulaire classique, le
  même cas donne un 403 « CSRF token invalid: reload the page », complété,
  si la requête n'a apporté aucun cookie de session, d'une alerte « Session
  cookie not stored (or expired) » qui invite à vérifier
  `PGPP_WEB_SESSION_HTTPS_ONLY` et les cookies (cookies bloqués par le
  navigateur, cookie `Secure` écarté d'une page servie en HTTP clair avec
  `PGPP_WEB_SESSION_HTTPS_ONLY=true`). Une requête sans aucun jeton (client
  qui n'a chargé aucune page) reçoit seulement « CSRF token missing:
  fetch a page first ». Le jeton n'est publié que dans `hx-headers` (pas de
  balise `<meta>`).
- **En-têtes** : `Content-Security-Policy` sans script inline (nonce par
  requête, `script-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store` sur toutes les
  pages. Les fichiers de `/static` sont mis en cache une heure ; leur URL porte
  une empreinte courte de leur contenu (`?v=<hash>`, calculée au démarrage) :
  après une mise à jour, le navigateur charge la nouvelle version sans
  attendre l'expiration du cache. HTMX est durci via `<meta name="htmx-config">` (`allowEval: false`,
  `allowScriptTags: false`, `selfRequestsOnly: true`).
- **Journaux** : une fabrique de `LogRecord`, exécutée une seule fois par
  enregistrement et valable pour tous les loggers et handlers, masque toute
  valeur associée à `password`, `passwd`, `pwd`,
  `secret`, `token`, dans les arguments et le message une fois formaté
  (`"password=%s"` et son argument), quel que soit le logger (y compris ceux
  d'uvicorn). Les attributs `extra`, posés par `Logger.makeRecord` après la
  fabrique, sont masqués par une surcharge de `makeRecord` installée sur la
  classe `Logger` elle-même (loggers déjà créés et logger racine compris) :
  un formateur qui lit directement `record.__dict__` (JSON par exemple) ne
  voit que des valeurs masquées. Un gabarit cassé (plus de `%s` que
  d'arguments) est gardé masqué, ses arguments supprimés : `logging` ne les
  imprime donc pas bruts dans son rapport d'erreur. Le gabarit n'est jamais masqué seul : il
  perdrait son `%s` et la ligne avec lui. Quand seul le message assemblé
  contient une valeur sensible, il remplace le gabarit et les arguments
  restent en place, en même nombre : le formateur d'accès d'uvicorn, qui en
  attend cinq, produit toujours sa ligne (`GET /audit?role=token:` par
  exemple). Pour ne pas formater chaque ligne deux fois, la fabrique ne
  construit le message que s'il peut contenir un secret (un de ces mots dans
  le gabarit ou dans un argument texte, ou un argument d'un autre type que
  texte, nombre, booléen ou `None`) ou si son formatage peut échouer : les
  autres lignes ne sont formatées qu'une fois, par leur handler. Les
  conteneurs exacts (`dict`, `list`, `tuple`) sont reconstruits masqués ;
  une sous-classe (`namedtuple`, `defaultdict`, `OrderedDict`) est gardée
  telle quelle si rien n'y est sensible, remplacée sinon par le texte masqué
  de son contenu, et le masquage ne lève jamais d'exception (`***` en
  dernier recours). Limite connue : un enregistrement reconstruit par
  `logging.makeLogRecord()` échappe au masquage (la fabrique reçoit un
  enregistrement vide, ses attributs sont posés ensuite), de même que les
  `extra` d'une sous-classe de `Logger` qui redéfinit `makeRecord` sans
  l'appeler. L'application elle-même
  ne journalise jamais de mot de passe ; le filtre est un filet de sécurité.
- **Authentification** : bcrypt pour HTTP basic (comparaison à coût constant,
  même pour un utilisateur inconnu : il est comparé à une empreinte factice du
  même coût que celles de `PGPP_WEB_BASIC_USERS`, qui doivent donc toutes
  avoir le même coût, faute de quoi l'application refuse de démarrer), chaque
  échec journalisé avec le pair et le nom d'utilisateur (assaini), jamais le
  mot de passe ; la limitation de débit revient au reverse proxy (voir plus
  haut). En mode proxy, l'en-tête
  n'est accepté que depuis un pair de confiance. Aucune route de documentation
  OpenAPI n'est exposée.
- **Erreurs** : seuls les refus de l'extension sont affichés tels quels dans
  les fragments d'action (422) : SQLSTATE qu'elle lève (`42501`, `42704`,
  `42710`, `55006`, `53400`, `28P01`, `P0001`), erreurs dues aux valeurs
  saisies (classes `22`, intervalle illisible par exemple, et `23`,
  contrainte `CHECK` d'un profil) et message préfixé `pg_pass_policy:` ou
  `PPP-0xx`, sauf avec un SQLSTATE interne (classes `XX` et `42` hors
  `42501`, `42704`, `42710`) : `XX000` ou `42703` signalent un défaut de
  l'extension ou un décalage de version, traités comme ci-après (page 500,
  une seule ligne `ERROR` avec le SQLSTATE). Un `55000` n'est jamais un
  refus, quel que soit son message : `PPP-004` (schéma non fiable) donne
  lui aussi la page 500. Cela vaut aussi pour « could not
  generate a password compliant with profile » (`XX000`), visible dans le
  seul journal du serveur. Toute autre erreur PostgreSQL (vue ou fonction absente, pool,
  connexion perdue), y compris pendant une action, est journalisée en `ERROR`
  (une seule ligne, avec son SQLSTATE) et donne une page 500 générique : le texte complet (noms de tables, détails
  de connexion libpq) ne va qu'au journal du serveur. Une erreur générique survenue pendant un échange HTMX (422 de
  validation, 404, 500, 503) est renvoyée avec `HX-Retarget: #alerts` et
  `HX-Reswap: innerHTML` : l'alerte s'affiche dans la zone d'alertes de la page
  et l'élément visé (ligne de rôle, formulaire) reste en place. Un client non
  identifié (404 ou 405 du routeur, levées avant l'authentification, 401, 403)
  reçoit une page d'erreur minimale, sans navigation ni lien. `worker_status()`
  donne « worker not running », avec un avertissement au journal, pour une
  erreur `55000` autre qu'une extension indisponible, un droit manquant
  (`42501`) ou une fonction absente (`42883`) : le tableau de bord reste
  lisible avec des droits partiels. Une connexion perdue ou toute autre
  erreur reste une erreur 500, l'extension non préchargée ou non installée
  donne la page dédiée (voir ci-dessous), y compris sur `/maintenance`.
  Un refus de suppression de profil envoyé sans HTMX donne une page d'erreur
  complète, pas un fragment isolé. Si `switch_rotation_pair()` ne renvoie
  aucune ligne, la bascule est validée mais le mot de passe est inconnu :
  l'application répond 200 avec un avertissement (erreur journalisée) et la
  liste des paires relue normalement, sans inviter à recommencer la bascule.
  De même, une rotation validée dont `rotate_password()` renvoie `NULL` ou une
  chaîne vide répond 200 avec un avertissement (erreur journalisée) et la
  ligne du rôle relue normalement, jamais un mot de passe affiché « None ».
- **Bibliothèque non préchargée** : sans `pg_pass_policy` dans
  `shared_preload_libraries`, les vues (`v_role_status` appelle
  `failed_attempts()`) et les actions échouent toutes avec le SQLSTATE `55000`.
  La première requête de la page qui le reçoit interrompt la requête HTTP :
  l'application affiche alors une page dédiée « pg_pass_policy is not
  preloaded » (503) avec le message et le `HINT` du serveur, ou, pendant un
  échange HTMX, une alerte dans la zone d'alertes. Seul ce cas est reconnu
  (message ou `HINT` citant `shared_preload_libraries`, mémoire partagée non
  initialisée), ainsi que l'extension non installée dans la base, qui
  donne sa propre page « not installed » (503, avec le message du serveur) :
  tout autre `55000` donne la page 500 générique. Sans l'extension, la
  première requête échoue en `3F000` (« schema "pass_policy" does not
  exist », appel d'une fonction `pass_policy.*`), reconnu directement, ou en
  `42P01` (vue `pass_policy.*` absente) : ce dernier cas pouvant aussi venir
  d'une extension installée mais décalée, l'application vérifie alors
  `pg_extension` avant d'afficher la page dédiée (sinon page 500). Seul le
  SQLSTATE compte, jamais le texte du message, que le serveur traduit
  selon `lc_messages` (« le schéma « pass_policy » n'existe pas »). Le
  `55000` « pg_pass_policy is not installed in this database » du serveur
  donne la même page.
- **Noms dans les URL** : un nom de rôle ou de paire peut contenir `/` ; il est
  encodé (`%2F`), le serveur le décode avant le routage et les routes
  `/{role:path}/action` le reconstituent. Les routes d'un profil sont rangées sous
  `/profiles/p/{name}` (édition, mise à jour, `/profiles/p/{name}/delete`),
  à l'écart des routes fixes `/profiles/new`, `/profiles/assign` et
  `/profiles/unassign` : un profil nommé `new` ou `assign` se gère donc comme
  les autres. Elles gardent un segment simple : la contrainte `CHECK (name ~
  '^[A-Za-z0-9_.-]{1,63}$')` de `pass_policy.profile` interdit `/` (un profil
  `x/delete` ne peut pas exister, ce que vérifie un test d'intégration). Seuls
  `.` et `..` (segments supprimés de l'URL par le navigateur), acceptés par
  l'extension, restent injoignables : l'interface refuse de créer un profil
  portant l'un d'eux (422, message explicite) ; son formulaire d'édition, sa
  modification et sa suppression répondent 404 « profile "…" cannot be
  managed from this interface » (même garde, avant toute requête, sans
  affirmer que le profil existe) ; dans la liste des profils, un tel profil
  n'a ni lien d'édition ni bouton de suppression (mention « SQL only ») : il
  se gère en SQL.
- **Droits** : le rôle de service est seulement membre de `pass_policy_admin` ;
  les fonctions `SECURITY DEFINER` qui visent un rôle (rotation, expiration,
  verrouillage, paires, `assign_profile()` et `unassign_profile()`) refusent
  de toucher aux rôles privilégiés (`_require_target_allowed()`), et l'erreur
  est affichée telle quelle (422) : l'application ne refait pas ce contrôle.
  Si le rôle de service n'est pas superutilisateur, les rôles privilégiés sont
  simplement absents du formulaire d'assignation. Ce filtre d'affichage
  (`db.login_roles()`) n'a pas de copie de la règle : il appelle le prédicat
  de l'extension, `pass_policy._is_privileged(oid)` (exécutable par
  `pass_policy_viewer` et `pass_policy_admin`), sur le rôle et sur chacun des
  rôles dont il est membre, même indirectement (`pg_has_role`), comme
  `_require_target_allowed()`. L'ensemble des rôles privilégiés est calculé
  une fois par requête (une évaluation de la fonction `STABLE` par rôle),
  puis chaque rôle de connexion est comparé à cette courte liste : environ
  35 ms pour 2 000 rôles. Un test d'intégration vérifie que le formulaire
  propose exactement les rôles que l'extension accepte sur un jeu de rôles.
- **Rôles renommés** : après `ALTER ROLE … RENAME`, les colonnes `role_name` de
  `role_state` et `role_profile` gardent l'ancien nom jusqu'au passage suivant
  de `run_maintenance()`. L'application les joint par OID (`role_oid`) : le
  tableau des rôles (motif de verrouillage) et la liste des assignations
  affichent toujours le nom courant.
- **Transactions** : chaque requête utilise une connexion du pool dans une
  transaction validée quand la fonction de la route se termine, **avant**
  l'envoi de la réponse (dépendance déclarée avec `scope="function"` : depuis
  FastAPI 0.118, une dépendance `yield` ordinaire n'est fermée qu'après l'envoi).
  La requête qui suit un 303 ou un `HX-Redirect` voit donc la modification, et
  un échec du `COMMIT` donne une page 500 au lieu d'une redirection trompeuse.
  Chaque action passe par `db.run_action()` : appel de la fonction
  `pass_policy.*` dans un point de sauvegarde (un refus de l'extension est
  annulé seul et affiché en 422, la connexion reste utilisable pour la
  réponse ; toute autre erreur remonte en 500, voir Erreurs), puis
  `COMMIT` immédiat, avant toute relecture : l'extension n'applique qu'au
  `COMMIT` ses changements en mémoire partagée (verrou, compteur d'échecs).
- **Affichage unique** : le fragment d'une rotation remplace tout le `<tbody>`
  du rôle (ligne + note) ; la prochaine action sur le même rôle, ou tout autre
  échange HTMX sur la page, retire le mot de passe affiché (`htmx:beforeSwap`
  dans `app.js`), de même que le déchargement de la page (`pagehide`). La
  rotation et la bascule de paire sont validées (`COMMIT`) avant tout affichage :
  un mot de passe n'est montré qu'une fois appliqué. Si la relecture qui suit
  (ligne du rôle, liste des paires) échoue, le mot de passe est affiché quand
  même, avec un avertissement invitant à recharger la page : il n'existe nulle
  part ailleurs. Les deux routes partagent `db.reread_after_commit()`, qui
  journalise l'échec et renvoie le résultat ou l'avertissement. La
  maintenance manuelle l'utilise aussi pour relire l'état du worker après son
  `COMMIT` : un échec de cette relecture affiche les actions effectuées avec
  un avertissement, au lieu d'une page 500 qui inviterait à relancer.

## Tests

```sh
ruff check .
ruff format --check .
pytest                     # tests unitaires seuls : 193 (27 tests d'intégration ignorés)
```

Les tests d'intégration ont besoin d'une base réelle avec l'extension
chargée ; ils sont ignorés quand `PGPP_TEST_URL` est absente. Le script
`scripts/test-instance.sh` crée une instance temporaire (initdb, port TCP
local, scram-sha-256, extension installée depuis le `pg_config` du `PATH`, rôle
`pgpp_web` membre de `pass_policy_admin` avec `CREATEROLE` pour les besoins
des tests) et affiche les variables à exporter ; les mots de passe générés vont
dans un fichier `pgpass` (0600), jamais sur une ligne de commande. Le script
ne supprime (`rm -rf`) que le répertoire qu'il a lui-même créé, reconnu à son
fichier marqueur `.pgpp-web-test-instance` : un répertoire existant non vide
sans ce marqueur est refusé, à `start` comme à `stop` :

```sh
eval "$(scripts/test-instance.sh start /tmp/pgpp-web-test 54332)"
pytest                     # 220 tests : unitaires + intégration
scripts/test-instance.sh stop /tmp/pgpp-web-test
```

Variables : `PGPP_TEST_URL` (connexion utilisée par l'application testée),
`PGPP_TEST_SUPER_URL` (superutilisateur, facultatif, pour créer et supprimer
les rôles de test `web_t_*`), `PGPASSFILE`. Les tests d'intégration couvrent le
tableau de bord, la liste et les filtres des rôles, la rotation (le mot de passe
figure dans la réponse et nulle part ailleurs : ni dans les journaux capturés,
ni dans l'audit, et il permet réellement de se connecter), lock / unlock /
expire, les profils (création visible dès la requête suivante, modification,
assignation, suppression, noms réservés, refus d'assignation sur un rôle
privilégié, profil `assign` créé en SQL, formulaire d'assignation limité aux rôles que l'extension
accepte, rôle renommé),
l'audit (filtres, pagination), les
paires de rotation, la maintenance, le refus CSRF, les pages « extension non
préchargée » (erreur `55000` levée par le serveur avec son `HINT`) et
« extension non installée » (dont une vraie base créée sans l'extension :
`42P01` sur le tableau de bord, `3F000` sur `/maintenance`), le tableau de bord avec des droits partiels
sur `worker_status()` et la
page 500 journalisée d'une erreur inattendue pendant une action.

## Arborescence

```
web/
├── pyproject.toml           projet pgpp-web (extras dev : pytest, httpx, ruff)
├── app/
│   ├── main.py              factory FastAPI, middlewares, gestion des erreurs
│   ├── config.py            Settings (pydantic-settings, préfixe PGPP_WEB_)
│   ├── db.py                pool psycopg et requêtes (fonctions et vues pass_policy)
│   ├── auth.py              HTTP basic (bcrypt) / en-tête de reverse proxy
│   ├── csrf.py              jeton de session et vérification
│   ├── security.py          en-têtes de sécurité (CSP avec nonce, no-store…)
│   ├── logfilter.py         masquage des mots de passe dans les journaux
│   ├── templating.py        Jinja2, filtres, configuration HTMX
│   ├── hashpw.py            commande pgpp-web-hash
│   ├── routers/             dashboard, roles, profiles, audit, pairs, maintenance
│   ├── templates/           pages et fragments HTMX
│   └── static/              htmx.min.js, app.js (bouton copier), app.css
├── scripts/test-instance.sh instance PostgreSQL temporaire pour les tests
└── tests/                   unitaires et intégration (PGPP_TEST_URL)
```
