--
-- 90_privileges — droits : utilisateur ordinaire, pass_policy_viewer,
-- pass_policy_admin (SPEC §3, §8.4)
--
-- SET SESSION AUTHORIZATION change session_user : c'est lui que vérifient les
-- fonctions SECURITY DEFINER (pg_has_role(session_user, …) OR rolsuper).
-- Refus attendu : SQLSTATE 42501 (insufficient_privilege), que le refus vienne
-- du REVOKE EXECUTE ou du contrôle interne.
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_user LOGIN;
CREATE ROLE regress_viewer LOGIN IN ROLE pass_policy_viewer;
CREATE ROLE regress_admin LOGIN IN ROLE pass_policy_admin;
CREATE ROLE regress_target LOGIN;
CREATE ROLE regress_super LOGIN SUPERUSER;
-- Rôles privilégiés par appartenance (SET ROLE / INHERIT donnent les droits)
CREATE ROLE regress_proxy LOGIN;            -- membre direct d'un superutilisateur
GRANT regress_super TO regress_proxy;
CREATE ROLE regress_mid NOLOGIN;
GRANT regress_super TO regress_mid;
CREATE ROLE regress_proxy2 LOGIN;           -- membre transitif (via regress_mid)
GRANT regress_mid TO regress_proxy2;
CREATE ROLE regress_etl LOGIN;              -- membre d'un rôle prédéfini dangereux
GRANT pg_execute_server_program TO regress_etl;
CREATE ROLE regress_grp_super NOLOGIN;      -- groupe membre d'un superutilisateur
GRANT regress_super TO regress_grp_super;
-- CREATEROLE : privilégié sur PostgreSQL <= 15 (s'accorder pg_*, changer le
-- mot de passe de tout non-superutilisateur), et donc aussi ses membres
CREATE ROLE regress_cr_grp NOLOGIN CREATEROLE;
CREATE ROLE regress_cr_member LOGIN;        -- membre d'un rôle CREATEROLE
GRANT regress_cr_grp TO regress_cr_member;
CREATE ROLE regress_cr_sub NOLOGIN;         -- groupe membre d'un rôle CREATEROLE
GRANT regress_cr_grp TO regress_cr_sub;
CREATE ROLE regress_pair_grp NOLOGIN;       -- groupe applicatif ordinaire, propriétaire de la base
CREATE TEMP TABLE dbowner AS
  SELECT pg_get_userbyid(datdba) AS o FROM pg_database WHERE datname = current_database();
DO $$BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO regress_pair_grp', current_database()); END$$;

-- Utilisateur ordinaire --------------------------------------------------
SET SESSION AUTHORIZATION regress_user;
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_target')$$) AS rotate;
SELECT ppp_test.try($$SELECT pass_policy.expire_password('regress_target')$$) AS expire;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_target')$$) AS lock;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_target')$$) AS unlock;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_hack')$$) AS create_profile;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('default', '{"min_length": 1}')$$) AS alter_profile;
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_user', 'default')$$) AS assign_profile;
SELECT ppp_test.try($$SELECT pass_policy.load_dictionary(ARRAY['x'])$$) AS load_dictionary;
SELECT ppp_test.try($$SELECT * FROM pass_policy.run_maintenance()$$) AS run_maintenance;
SELECT ppp_test.try($$SELECT pass_policy.purge_audit()$$) AS purge_audit;
SELECT ppp_test.try($$SELECT pass_policy.audit('maintenance', 'regress_user')$$) AS forge_audit;
SELECT ppp_test.try($$SELECT pass_policy.shmem_unlock_role('regress_target')$$) AS shmem_unlock;
SELECT ppp_test.try($$SELECT pass_policy.shmem_lock_role('regress_target', NULL)$$) AS shmem_lock;
SELECT ppp_test.try($$SELECT * FROM pass_policy.switch_rotation_pair('app')$$) AS switch_pair;
-- record_password_change : refusé pour un autre rôle ET pour soi-même : un appel
-- direct permettrait de falsifier l'historique ou de repousser l'expiration sans
-- changer de mot de passe. Seul le hook (contexte privilégié) l'appelle.
SELECT ppp_test.try($$SELECT pass_policy.record_password_change('regress_target', 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw=')$$) AS record_other;
SELECT ppp_test.try($$SELECT pass_policy.record_password_change('regress_user', 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw=')$$) AS record_self;
-- ... et refusé aussi en superutilisateur hors du hook : seul le hook C peut
-- enregistrer un changement (sinon un admin non superutilisateur pourrait
-- rouvrir un compte superutilisateur expiré sans changer son mot de passe).
RESET SESSION AUTHORIZATION;
SELECT ppp_test.try($$SELECT pass_policy.record_password_change('regress_target', 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw=')$$) AS record_as_superuser;
SET SESSION AUTHORIZATION regress_user;
-- Lecture directe des tables et vues : refusée
SELECT ppp_test.try($$SELECT * FROM pass_policy.profile$$) AS sel_profile;
SELECT ppp_test.try($$SELECT * FROM pass_policy.password_history$$) AS sel_history;
SELECT ppp_test.try($$SELECT * FROM pass_policy.audit_log$$) AS sel_audit;
SELECT ppp_test.try($$SELECT * FROM pass_policy.role_state$$) AS sel_state;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_role_status$$) AS sel_status;
SELECT ppp_test.try($$SELECT * FROM pass_policy.failed_attempts()$$) AS failed_attempts;
-- Écriture directe : refusée
SELECT ppp_test.try($$DELETE FROM pass_policy.password_history$$) AS del_history;
SELECT ppp_test.try($$UPDATE pass_policy.role_state SET locked_until = NULL$$) AS upd_state;
RESET SESSION AUTHORIZATION;
-- L'appel record_self n'a pas laissé de vérificateur visible dans l'audit
SELECT ppp_test.leaks();

-- Aucun droit pour PUBLIC : les requêtes SPI du hook tournent en
-- superutilisateur (ppp_spi_begin), ni USAGE sur le schéma ni EXECUTE sur
-- effective_profile(), record_password_change() ou audit() ne sont nécessaires
SELECT has_schema_privilege('regress_user', 'pass_policy', 'USAGE') AS user_usage,
       has_function_privilege('regress_user', 'pass_policy.effective_profile(name)', 'EXECUTE') AS user_effective_profile,
       has_function_privilege('regress_user', 'pass_policy.record_password_change(text, text)', 'EXECUTE') AS user_record,
       has_function_privilege('regress_user', 'pass_policy.audit(text, text, jsonb)', 'EXECUTE') AS user_audit;
SELECT has_function_privilege('regress_viewer', 'pass_policy.effective_profile(name)', 'EXECUTE') AS viewer_effective_profile,
       has_function_privilege('regress_viewer', 'pass_policy.audit(text, text, jsonb)', 'EXECUTE') AS viewer_audit,
       has_function_privilege('regress_admin', 'pass_policy.audit(text, text, jsonb)', 'EXECUTE') AS admin_audit,
       has_function_privilege('regress_admin', 'pass_policy.record_password_change(text, text)', 'EXECUTE') AS admin_record;
-- … et l'utilisateur ordinaire change toujours SON mot de passe : politique
-- appliquée, changement enregistré
INSERT INTO ppp_test.secrets VALUES ('user_own', 'Own-Password#2026x');
SET SESSION AUTHORIZATION regress_user;
SELECT ppp_test.try($$ALTER ROLE regress_user PASSWORD 'weak'$$) AS user_own_weak;
SELECT ppp_test.try($$ALTER ROLE regress_user PASSWORD 'Own-Password#2026x'$$) AS user_own_password;
RESET SESSION AUTHORIZATION;
SELECT count(*) AS user_history_rows FROM pass_policy.password_history
 WHERE role_oid = 'regress_user'::regrole::oid;
SELECT password_changed_at > now() - interval '1 minute' AS user_change_recorded
  FROM pass_policy.role_state WHERE role_oid = 'regress_user'::regrole::oid;
SELECT count(*) AS user_changed_events FROM pass_policy.audit_log
 WHERE role_name = 'regress_user' AND event_type = 'password_changed';

-- Viewer -----------------------------------------------------------------
SET SESSION AUTHORIZATION regress_viewer;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_role_status$$) AS sel_status;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_expiring$$) AS sel_expiring;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_locked$$) AS sel_locked;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_recent_audit$$) AS sel_recent_audit;
SELECT ppp_test.try($$SELECT * FROM pass_policy.profile$$) AS sel_profile;
SELECT count(*) > 0 AS sees_roles FROM pass_policy.v_role_status;
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_target')$$) AS rotate;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_target')$$) AS lock;
SELECT ppp_test.try($$UPDATE pass_policy.profile SET min_length = 1$$) AS upd_profile;
RESET SESSION AUTHORIZATION;

-- Admin (membre de pass_policy_admin, non superutilisateur) ---------------
SET SESSION AUTHORIZATION regress_admin;
SELECT rolsuper FROM pg_roles WHERE rolname = session_user;
INSERT INTO ppp_test.secrets
  SELECT 'admin_rot', pass_policy.rotate_password('regress_target');
-- check_password() par un admin sur un autre rôle : ni historique ni min_age
-- (regress_target vient de changer de mot de passe, min_age = 1 jour) ; sinon
-- PPP-030 renseignerait sur la date du dernier changement d'un autre rôle
INSERT INTO ppp_test.secrets VALUES ('admin_check', 'Unrelated-Valid#2026x');
SELECT ppp_test.code(pass_policy.check_password('regress_target', 'Unrelated-Valid#2026x')) AS admin_check_other;
-- ... mais un admin qui peut changer ce mot de passe (CREATEROLE et ADMIN
-- OPTION sur regress_target : le prédicat du hook, PPP_MAY_SET_PASSWORD_OF,
-- vrai sur PG 14-15 comme sur PG >= 16) voit l'historique et min_age : PPP-030
RESET SESSION AUTHORIZATION;
CREATE ROLE regress_hadmin LOGIN CREATEROLE IN ROLE pass_policy_admin;
GRANT regress_target TO regress_hadmin WITH ADMIN OPTION;
SET SESSION AUTHORIZATION regress_hadmin;
SELECT ppp_test.code(pass_policy.check_password('regress_target', 'Unrelated-Valid#2026x')) AS admin_option_check_other;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION regress_admin;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_target', interval '1 hour', 'admin test')$$) AS lock;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_target')$$) AS unlock;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_admin', '{"min_length": 14}')$$) AS create_profile;
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_target', 'p_admin')$$) AS assign_profile;
SELECT ppp_test.try($$SELECT pass_policy.unassign_profile('regress_target')$$) AS unassign_profile;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('p_admin')$$) AS drop_profile;
SELECT ppp_test.try($$SELECT count(*) FROM pass_policy.run_maintenance()$$) AS run_maintenance;
-- rebind_restored_roles() : superutilisateur seulement (aucun GRANT)
SELECT ppp_test.try($$SELECT count(*) FROM pass_policy.rebind_restored_roles()$$) AS rebind_restored;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_role_status$$) AS sel_status;
-- Exigence de sécurité (proposée) : un admin non superutilisateur ne peut pas
-- changer le mot de passe d'un superutilisateur (prise de contrôle)
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_super')$$) AS rotate_superuser;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_super')$$) AS lock_superuser;
-- ... ni lui assigner ou retirer un profil (verrouillage ou expiration d'un
-- superutilisateur par un profil agressif)
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_super', 'default')$$) AS assign_superuser;
SELECT ppp_test.try($$SELECT pass_policy.unassign_profile('regress_super')$$) AS unassign_superuser;
-- ... ni d'un rôle qui en hérite : membre direct, transitif, ou d'un rôle pg_*
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_proxy')$$) AS rotate_member_of_super;
SELECT ppp_test.try($$SELECT pass_policy.expire_password('regress_proxy')$$) AS expire_member_of_super;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_proxy')$$) AS lock_member_of_super;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_proxy')$$) AS unlock_member_of_super;
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_proxy2')$$) AS rotate_transitive_member;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_proxy2')$$) AS lock_transitive_member;
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_etl')$$) AS rotate_member_of_pg_role;
SELECT ppp_test.try($$SELECT pass_policy.expire_password('regress_etl')$$) AS expire_member_of_pg_role;
-- create_rotation_pair : le GRANT du groupe est exécuté en superutilisateur,
-- un groupe privilégié (ou membre d'un rôle privilégié) est donc refusé …
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_super', 'regress_pair_x', 'regress_pair_y', 'regress_super')$$) AS pair_on_superuser;
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_pg', 'regress_pair_x', 'regress_pair_y', 'pg_execute_server_program')$$) AS pair_on_predefined;
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_grp', 'regress_pair_x', 'regress_pair_y', 'regress_grp_super')$$) AS pair_on_member_of_super;
-- CREATEROLE (PG <= 15 seulement) : le même prédicat _is_privileged() vaut
-- pour la cible et pour chacun des rôles dont elle est membre ; sur PG >= 16
-- CREATEROLE n'est plus privilégié et les trois appels réussissent. Sortie
-- indépendante de la version.
SELECT (ppp_test.try($$SELECT pass_policy.lock_role('regress_cr_grp')$$) = '42501')
       = (current_setting('server_version_num')::int < 160000) AS createrole_rule;
SELECT (ppp_test.try($$SELECT pass_policy.lock_role('regress_cr_member')$$) = '42501')
       = (current_setting('server_version_num')::int < 160000) AS createrole_member_rule;
BEGIN;
SELECT (ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_cr', 'regress_pair_c1', 'regress_pair_c2', 'regress_cr_sub')$$) = '42501')
       = (current_setting('server_version_num')::int < 160000) AS createrole_group_rule;
ROLLBACK;
-- … et l'exception annule le CREATE ROLE
SELECT count(*) AS pair_roles_created FROM pg_roles WHERE rolname IN ('regress_pair_x', 'regress_pair_y');
SELECT count(*) AS pair_rows FROM pass_policy.rotation_pair WHERE pair_name LIKE 'pair\_%';
-- Groupe applicatif ordinaire, même propriétaire de la base (membre implicite
-- de pg_database_owner) : accepté
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_ok', 'regress_pair_x', 'regress_pair_y', 'regress_pair_grp')$$) AS pair_on_plain_group;
SELECT count(*) AS pair_roles_created FROM pg_roles WHERE rolname IN ('regress_pair_x', 'regress_pair_y');
RESET SESSION AUTHORIZATION;
SELECT length(pwd) AS admin_rot_len FROM ppp_test.secrets WHERE label = 'admin_rot';
SELECT actor FROM pass_policy.audit_log
 WHERE event_type = 'password_rotated' AND role_name = 'regress_target'
 ORDER BY id DESC LIMIT 1;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_super')$$) AS cleanup_unlock_super;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_cr_grp')$$) AS cleanup_unlock_cr_grp;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_cr_member')$$) AS cleanup_unlock_cr_member;
-- En superutilisateur, les mêmes cibles sont acceptées
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_proxy')$$) AS super_lock_member;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_proxy')$$) AS super_unlock_member;
INSERT INTO ppp_test.secrets SELECT 'super_rot_etl', pass_policy.rotate_password('regress_etl');
SELECT length(pwd) AS super_rot_etl_len FROM ppp_test.secrets WHERE label = 'super_rot_etl';
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_super', 'regress_pair_s', 'regress_pair_t', 'regress_grp_super')$$) AS super_pair_on_member_of_super;
DO $$BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), (SELECT o FROM dbowner)); END$$;

-- ---------------------------------------------------------------------
-- Extension présente mais schéma non fiable (re-possédé par un non
-- superutilisateur) : le hook refuse explicitement (PPP-004) au lieu de
-- n'appliquer aucune politique ; check_password() aussi.
-- ---------------------------------------------------------------------
SELECT nspowner::regrole AS ppp_owner FROM pg_namespace WHERE nspname = 'pass_policy' \gset
ALTER SCHEMA pass_policy OWNER TO regress_user;
SELECT ppp_test.try($$ALTER ROLE regress_target PASSWORD 'Untrusted-Schema#2026'$$) AS untrusted_alter;
SELECT ppp_test.try($$SELECT pass_policy.check_password('regress_target', 'Untrusted-Schema#2026')$$) AS untrusted_check;
ALTER ROLE regress_target PASSWORD 'Untrusted-Schema#2026';
ALTER SCHEMA pass_policy OWNER TO :"ppp_owner";
INSERT INTO ppp_test.secrets VALUES ('untrusted', 'Untrusted-Schema#2026');
SELECT ppp_test.try($$ALTER ROLE regress_target PASSWORD 'Untrusted-Schema#2026'$$) AS trusted_again;

-- ---------------------------------------------------------------------
-- Pas d'oracle par CREATE ROLE / ALTER ROLE : un rôle CREATEROLE sans ADMIN
-- sur regress_target (mot de passe courant 'Untrusted-Schema#2026') ne doit
-- jamais obtenir PPP-031 (« déjà utilisé ») ni PPP-030 pour lui. PostgreSQL
-- teste l'existence du rôle (CREATE ROLE : 42710) et le droit de le modifier
-- (ALTER ROLE) avant d'appeler le hook ; le hook ne fait de toute façon les
-- contrôles d'historique et de min_age que si l'appelant peut changer ce mot
-- de passe. Un mot de passe faible donne aussi 42710 (la complexité ne
-- révélerait que la faiblesse du candidat, pas le mot de passe d'un autre).
-- ALTER ROLE : refusé (42501) sur PG >= 16 sans ADMIN ; sur PG <= 15,
-- CREATEROLE suffit à changer le mot de passe d'un non-superutilisateur, la
-- réponse n'apprend donc rien qu'il ne puisse déjà faire : PPP-030 (min_age,
-- contrôlé avant la réutilisation PPP-031, le mot de passe de regress_target
-- venant d'être changé).
-- ---------------------------------------------------------------------
CREATE ROLE regress_creator LOGIN CREATEROLE;
SET SESSION AUTHORIZATION regress_creator;
SELECT ppp_test.try($$CREATE ROLE regress_target PASSWORD 'Untrusted-Schema#2026'$$) AS create_existing_current;
SELECT ppp_test.try($$CREATE ROLE regress_target PASSWORD 'weak'$$) AS create_existing_weak;
SELECT ppp_test.try($$ALTER ROLE regress_target PASSWORD 'Untrusted-Schema#2026'$$)
       = CASE WHEN current_setting('server_version_num')::int >= 160000
              THEN '42501' ELSE '28P01 PPP-030' END AS alter_other_current;
RESET SESSION AUTHORIZATION;

-- ---------------------------------------------------------------------
-- pg_pass_policy.exempt_roles : _is_exempt() appelle la fonction C des hooks
-- (ppp_role_is_exempt(), règles de SplitIdentifierString()) : noms non quotés
-- en minuscules, "quotés" tels quels ("" = un guillemet), espaces ignorés.
-- Le GUC est SIGHUP : pg_reload_conf() est asynchrone et le backend ne relit
-- la configuration qu'entre deux instructions ; l'attente (bornée à 5 s) est
-- donc faite d'une instruction par tour (\gexec), sortie masquée.
-- ---------------------------------------------------------------------
CREATE ROLE "Regress_Exempt Q" LOGIN;
CREATE ROLE regress_exempt_u LOGIN;
CREATE ROLE "Regress_Exempt_U" LOGIN;
ALTER SYSTEM SET pg_pass_policy.exempt_roles = ' a , b ,Postgres, "App User", "x""y", "Regress_Exempt Q" , REGRESS_EXEMPT_U';
SELECT pg_reload_conf();
\set ECHO none
\o /dev/null
SELECT format('SELECT pg_sleep(0.1) WHERE current_setting(%L) <> %L',
              'pg_pass_policy.exempt_roles',
              ' a , b ,Postgres, "App User", "x""y", "Regress_Exempt Q" , REGRESS_EXEMPT_U')
  FROM generate_series(1, 50) \gexec
\o
\set ECHO all
SHOW pg_pass_policy.exempt_roles;
SELECT c AS candidate, pass_policy._is_exempt(c) AS exempt
  FROM unnest(ARRAY['a', 'b', ' a ', 'A', 'postgres', 'Postgres', 'App User', 'app user',
                    '"App User"', 'x"y', 'x""y']) WITH ORDINALITY AS t(c, n)
 ORDER BY n;
SELECT pass_policy._is_exempt(NULL) IS NULL AS strict_null;
INSERT INTO ppp_test.secrets VALUES ('exempt_weak', 'exempt-weak');
SELECT r AS role_name, pass_policy._is_exempt(r) AS sql_exempt,
       ppp_test.try(format('ALTER ROLE %I PASSWORD %L', r, 'exempt-weak')) = 'ok' AS hook_exempt
  FROM unnest(ARRAY['Regress_Exempt Q', 'regress_exempt_u', 'Regress_Exempt_U']) r
 ORDER BY 1;
-- Rôle exempté : rotate_password() ne pose pas de VALID UNTIL (run_maintenance()
-- ne le resynchroniserait jamais), il relève seulement une borne passée
INSERT INTO ppp_test.secrets SELECT 'exempt_rot', pass_policy.rotate_password('regress_exempt_u');
SELECT rolvaliduntil IS NULL AS exempt_rotate_no_valid_until FROM pg_roles WHERE rolname = 'regress_exempt_u';
SELECT pass_policy.expire_password('regress_exempt_u');
INSERT INTO ppp_test.secrets SELECT 'exempt_rot2', pass_policy.rotate_password('regress_exempt_u');
SELECT rolvaliduntil = 'infinity' AS exempt_rotate_unblocked FROM pg_roles WHERE rolname = 'regress_exempt_u';
-- Rôle exempté dont le mot de passe est changé par un ALTER ROLE direct (le
-- hook ne l'enregistre pas) : run_maintenance() réconcilie l'historique puis
-- relève le VALID UNTIL posé par expire_password() (mode unblock), sans
-- jamais synchroniser (sync) ni signaler l'expiration d'un rôle exempté.
CREATE TEMP TABLE ex_m0 AS SELECT * FROM pass_policy.run_maintenance();
SELECT pass_policy.expire_password('regress_exempt_u');
SELECT rolvaliduntil <= now() AS exempt_blocked FROM pg_roles WHERE rolname = 'regress_exempt_u';
INSERT INTO ppp_test.secrets VALUES ('exempt_direct', 'exempt-direct-change');
ALTER ROLE regress_exempt_u PASSWORD 'exempt-direct-change';
SELECT action, details->>'reason' AS reason, details->>'mode' AS mode
  FROM pass_policy.run_maintenance() WHERE role_name = 'regress_exempt_u' ORDER BY action;
SELECT rolvaliduntil = 'infinity' AS exempt_direct_unblocked FROM pg_roles WHERE rolname = 'regress_exempt_u';
ALTER SYSTEM RESET pg_pass_policy.exempt_roles;
SELECT pg_reload_conf();
\set ECHO none
\o /dev/null
SELECT 'SELECT pg_sleep(0.1) WHERE current_setting(''pg_pass_policy.exempt_roles'') <> '''''
  FROM generate_series(1, 50) \gexec
\o
\set ECHO all
SHOW pg_pass_policy.exempt_roles;

-- ---------------------------------------------------------------------
-- Faux schéma pass_policy dans une autre base : le hook ne doit jamais
-- exécuter en superutilisateur les fonctions d'un schéma qui n'appartient pas
-- à l'extension. Le propriétaire de la base (non superutilisateur) crée un
-- schéma « pass_policy » avec une fonction effective_profile() piégée ; son
-- ALTER ROLE doit être refusé par PPP-003 et la fonction ne doit pas tourner.
-- ---------------------------------------------------------------------
SELECT current_user AS orig_user \gset
CREATE ROLE regress_fake_owner LOGIN NOSUPERUSER;
CREATE DATABASE regress_fake OWNER regress_fake_owner;
\c regress_fake regress_fake_owner
CREATE SCHEMA pass_policy;
CREATE TABLE pass_policy.trap(hit boolean);
CREATE FUNCTION pass_policy.effective_profile(name) RETURNS SETOF record
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO pass_policy.trap VALUES (true);
  ALTER ROLE regress_fake_owner SUPERUSER;
  RETURN;
END$$;
\set VERBOSITY terse
ALTER ROLE regress_fake_owner PASSWORD 'Fake-Schema-Probe-2026!';
\set VERBOSITY default
SELECT count(*) AS trap_hits FROM pass_policy.trap;
SELECT rolsuper FROM pg_roles WHERE rolname = 'regress_fake_owner';
\c contrib_regression :orig_user
DROP DATABASE regress_fake;
DROP ROLE regress_fake_owner;

SELECT ppp_test.leaks();
