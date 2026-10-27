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
| `/audit` | journal d'audit avec filtres (rôle, type, depuis) et pagination |
| `/pairs` | paires de rotation : liste, création, bascule avec affichage unique du mot de passe |
| `/maintenance` | exécution manuelle de `run_maintenance()` |
| `/healthz` | sonde de vie (sans authentification, ne touche pas la base) |

## Installation

Prérequis : Python ≥ 3.11, une base où `pg_pass_policy` est installée
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
peut pas agir sur les rôles `SUPERUSER`, `REPLICATION` ou `BYPASSRLS` : c'est
voulu par l'extension.

## Configuration

Tout passe par des variables d'environnement préfixées `PGPP_WEB_`.

| variable | défaut | rôle |
|---|---|---|
| `PGPP_WEB_DATABASE_URL` | *(vide)* | chaîne de connexion libpq (`postgresql://pgpp_web@hôte:5432/postgres`). Vide : les variables `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSFILE`… de libpq s'appliquent |
| `PGPP_WEB_SECRET` | **obligatoire** | clé de signature du cookie de session (jeton CSRF), 32 caractères minimum : `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` |
| `PGPP_WEB_AUTH` | `basic` | `basic` (HTTP basic) ou `proxy` (en-tête posé par un reverse proxy) |
| `PGPP_WEB_BASIC_USERS` | *(vide)* | mode `basic` : `user:hash-bcrypt,user2:hash-bcrypt` |
| `PGPP_WEB_PROXY_HEADER` | `X-Remote-User` | mode `proxy` : en-tête portant l'utilisateur authentifié (`REMOTE_USER` est accepté et correspond à `Remote-User`) |
| `PGPP_WEB_TRUSTED_PROXIES` | `127.0.0.1,::1` | mode `proxy` : adresses ou réseaux (CIDR) autorisés à poser l'en-tête ; `unix` pour un socket Unix ; `*` pour tout accepter (déconseillé) |
| `PGPP_WEB_SESSION_HTTPS_ONLY` | `false` | marque le cookie de session `Secure` et le nomme `__Host-pgpp_session` : **obligatoire derrière HTTPS** (voir Sécurité) |
| `PGPP_WEB_REALM` | `pg_pass_policy` | realm HTTP basic |
| `PGPP_WEB_POOL_MIN` / `PGPP_WEB_POOL_MAX` | `1` / `4` | taille du pool de connexions |
| `PGPP_WEB_POOL_TIMEOUT` | `10` | attente maximale (s) d'une connexion du pool |
| `PGPP_WEB_PAGE_SIZE` | `50` | taille de page de l'audit |
| `PGPP_WEB_APP_NAME` | `pgpp-web` | préfixe de l'`application_name` PostgreSQL |

### Comptes HTTP basic

Les mots de passe ne sont stockés qu'en empreinte bcrypt. La commande
`pgpp-web-hash` lit le mot de passe au clavier (sans écho) et affiche l'entrée
à placer dans `PGPP_WEB_BASIC_USERS` :

```sh
pgpp-web-hash alice
# Password: ...
# alice:$2b$12$...
export PGPP_WEB_BASIC_USERS='alice:$2b$12$...,bob:$2b$12$...'
```

Le nom de l'utilisateur web est enregistré dans `pass_policy.audit_log`
(colonne `application_name`, valeur `pgpp-web:alice`) : chaque action reste
attribuable à une personne même si tous passent par le même rôle PostgreSQL.

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
   `X-Remote-User` envoyé par le client.

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

Derrière HTTPS, `PGPP_WEB_SESSION_HTTPS_ONLY=true` est requis : le cookie de
session devient `__Host-pgpp_session` (`Secure`, `Path=/`, sans `Domain`),
qu'aucune autre origine du même site (autre sous-domaine, autre port, réponse
en HTTP clair) ne peut écraser.

Limitation de débit : l'application ne freine pas elle-même les tentatives
HTTP basic (bcrypt coût 12 ralentit chaque essai, mais rien n'arrête un
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
- **En-têtes** : `Content-Security-Policy` sans script inline (nonce par
  requête, `script-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store` sur toutes les
  pages. HTMX est durci via `<meta name="htmx-config">` (`allowEval: false`,
  `allowScriptTags: false`, `selfRequestsOnly: true`).
- **Journaux** : un filtre de logging (fabrique de `LogRecord` + `Filter` sur
  les handlers) masque toute valeur associée à `password`, `passwd`, `pwd`,
  `secret`, `token`, dans les messages, les arguments et les attributs `extra`,
  quel que soit le logger (y compris ceux d'uvicorn). L'application elle-même
  ne journalise jamais de mot de passe ; le filtre est un filet de sécurité.
- **Authentification** : bcrypt pour HTTP basic (comparaison à coût constant,
  même pour un utilisateur inconnu), chaque échec journalisé avec le pair et
  le nom d'utilisateur (assaini), jamais le mot de passe ; la limitation de
  débit revient au reverse proxy (voir plus haut). En mode proxy, l'en-tête
  n'est accepté que depuis un pair de confiance. Aucune route de documentation
  OpenAPI n'est exposée.
- **Erreurs** : les messages de l'extension (`pg_pass_policy: …`, `PPP-0xx`)
  sont affichés tels quels dans les fragments d'action (422) ; toute autre
  erreur PostgreSQL (vue, pool, droits) donne une page 500 générique, le texte
  complet (noms de tables, détails de connexion libpq) n'allant qu'au journal
  du serveur.
- **Droits** : le rôle de service est seulement membre de `pass_policy_admin` ;
  les fonctions `SECURITY DEFINER` de l'extension refusent de toucher aux rôles
  privilégiés. L'application applique la même règle de son côté : si le rôle
  de service n'est pas superutilisateur, les rôles `SUPERUSER`, `REPLICATION`
  et `BYPASSRLS` sont absents du formulaire d'assignation de profil et toute
  assignation ou désassignation forgée sur l'un d'eux est refusée (422).
- **Affichage unique** : le fragment d'une rotation remplace tout le `<tbody>`
  du rôle (ligne + note) ; la prochaine action sur le même rôle, ou tout autre
  échange HTMX sur la page, retire le mot de passe affiché (`htmx:beforeSwap`
  dans `app.js`), de même que le déchargement de la page (`pagehide`).

## Tests

```sh
ruff check .
pytest                     # tests unitaires seuls (auth, CSRF, filtre de log, configuration)
```

Les tests d'intégration ont besoin d'une base réelle avec l'extension
chargée ; ils sont ignorés quand `PGPP_TEST_URL` est absente. Le script
`scripts/test-instance.sh` crée une instance temporaire (initdb, port TCP
local, scram-sha-256, extension installée depuis le `pg_config` du `PATH`, rôle
`pgpp_web` membre de `pass_policy_admin` avec `CREATEROLE` pour les besoins
des tests) et affiche les variables à exporter ; les mots de passe générés vont
dans un fichier `pgpass` (0600), jamais sur une ligne de commande :

```sh
eval "$(scripts/test-instance.sh start /tmp/pgpp-web-test 54332)"
pytest                     # 48 tests : unitaires + intégration
scripts/test-instance.sh stop /tmp/pgpp-web-test
```

Variables : `PGPP_TEST_URL` (connexion utilisée par l'application testée),
`PGPP_TEST_SUPER_URL` (superutilisateur, facultatif, pour créer et supprimer
les rôles de test `web_t_*`), `PGPASSFILE`. Les tests d'intégration couvrent le
tableau de bord, la liste et les filtres des rôles, la rotation (le mot de passe
figure dans la réponse et nulle part ailleurs : ni dans les journaux capturés,
ni dans l'audit, et il permet réellement de se connecter), lock / unlock /
expire, les profils (création, modification, assignation, suppression, refus
d'assignation sur un rôle privilégié), l'audit (filtres, pagination), les
paires de rotation, la maintenance et le refus CSRF.

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
