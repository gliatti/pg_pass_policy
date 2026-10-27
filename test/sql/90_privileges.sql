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
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_target', interval '1 hour', 'admin test')$$) AS lock;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_target')$$) AS unlock;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_admin', '{"min_length": 14}')$$) AS create_profile;
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_target', 'p_admin')$$) AS assign_profile;
SELECT ppp_test.try($$SELECT pass_policy.unassign_profile('regress_target')$$) AS unassign_profile;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('p_admin')$$) AS drop_profile;
SELECT ppp_test.try($$SELECT count(*) FROM pass_policy.run_maintenance()$$) AS run_maintenance;
SELECT ppp_test.try($$SELECT * FROM pass_policy.v_role_status$$) AS sel_status;
-- Exigence de sécurité (proposée) : un admin non superutilisateur ne peut pas
-- changer le mot de passe d'un superutilisateur (prise de contrôle)
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_super')$$) AS rotate_superuser;
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_super')$$) AS lock_superuser;
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
-- En superutilisateur, les mêmes cibles sont acceptées
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_proxy')$$) AS super_lock_member;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_proxy')$$) AS super_unlock_member;
INSERT INTO ppp_test.secrets SELECT 'super_rot_etl', pass_policy.rotate_password('regress_etl');
SELECT length(pwd) AS super_rot_etl_len FROM ppp_test.secrets WHERE label = 'super_rot_etl';
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('pair_super', 'regress_pair_s', 'regress_pair_t', 'regress_grp_super')$$) AS super_pair_on_member_of_super;
DO $$BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), (SELECT o FROM dbowner)); END$$;

SELECT ppp_test.leaks();
