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
RESET SESSION AUTHORIZATION;
SELECT length(pwd) AS admin_rot_len FROM ppp_test.secrets WHERE label = 'admin_rot';
SELECT actor FROM pass_policy.audit_log
 WHERE event_type = 'password_rotated' AND role_name = 'regress_target'
 ORDER BY id DESC LIMIT 1;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_super')$$) AS cleanup_unlock_super;

SELECT ppp_test.leaks();
