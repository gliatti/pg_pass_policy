--
-- 60_lock_unlock — verrouillage manuel et temporaire (SPEC §3.3, §4, §6.3)
--
-- Les vrais échecs d'authentification sont testés par test/shell/lockout.sh :
-- pg_regress se connecte en trust, le hook d'authentification n'y voit aucun échec.
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_lock LOGIN;

-- Verrou manuel (durée NULL) : locked_until = infinity, locked_by = manual ;
-- lock_role() renvoie le locked_until posé
SELECT pass_policy.lock_role('regress_lock', NULL, 'regression test') = 'infinity' AS returned_infinity;
SELECT locked_until = 'infinity' AS infinite, locked_by, lock_reason
  FROM pass_policy.role_state WHERE role_name = 'regress_lock';
SELECT role_name FROM pass_policy.v_locked WHERE role_name = 'regress_lock';
SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_lock';
-- La shmem connaît le verrou (lu par le hook d'authentification)
SELECT role_name, locked_until = 'infinity' AS infinite
  FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock';
SELECT count(*) > 0 AS lock_audited FROM pass_policy.audit_log
 WHERE event_type = 'role_locked' AND role_name = 'regress_lock';

-- Re-verrouiller un rôle déjà verrouillé : pas d'erreur
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_lock')$$) AS relock;

-- Déverrouillage
SELECT pass_policy.unlock_role('regress_lock');
SELECT locked_until IS NULL AS unlocked, locked_by IS NULL AS no_locker
  FROM pass_policy.role_state WHERE role_name = 'regress_lock';
SELECT count(*) AS in_v_locked FROM pass_policy.v_locked WHERE role_name = 'regress_lock';
SELECT status <> 'locked' AS not_locked
  FROM pass_policy.v_role_status WHERE role_name = 'regress_lock';
SELECT count(*) AS shmem_locked FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_lock' AND locked_until IS NOT NULL;
SELECT coalesce(max(failed_count), 0) AS shmem_failures FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_lock';
SELECT count(*) > 0 AS unlock_audited FROM pass_policy.audit_log
 WHERE event_type = 'role_unlocked' AND role_name = 'regress_lock';
-- Déverrouiller un rôle non verrouillé : pas d'erreur
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_lock')$$) AS unlock_again;

-- Verrou temporaire (1 seconde), levé par run_maintenance après expiration
SELECT pass_policy.lock_role('regress_lock', interval '1 second', 'short lock')
       = now() + interval '1 second' AS returned_until;
SELECT locked_until > now() AND locked_until <= now() + interval '2 seconds' AS bounded
  FROM pass_policy.role_state WHERE role_name = 'regress_lock';
SELECT role_name FROM pass_policy.v_locked WHERE role_name = 'regress_lock';
SELECT locked_until IS NOT NULL AND locked_until <> 'infinity' AS shmem_timed
  FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock';
SELECT pg_sleep(1.5);
-- Résultat de run_maintenance non affiché (dépend de l'état global)
SELECT count(*) >= 0 AS maintenance_ran FROM pass_policy.run_maintenance();
SELECT locked_until IS NULL AS auto_unlocked
  FROM pass_policy.role_state WHERE role_name = 'regress_lock';
SELECT count(*) AS in_v_locked FROM pass_policy.v_locked WHERE role_name = 'regress_lock';
SELECT count(*) AS shmem_locked FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_lock' AND locked_until > now();

-- Rôle inexistant refusé
SELECT ppp_test.try($$SELECT pass_policy.lock_role('regress_no_such_role')$$) <> 'ok' AS unknown_lock_refused;
SELECT ppp_test.try($$SELECT pass_policy.unlock_role('regress_no_such_role')$$) <> 'ok' AS unknown_unlock_refused;

-- Fonctions shmem bas niveau
SELECT pass_policy.shmem_lock_role('regress_lock', NULL);
SELECT locked_until = 'infinity' AS infinite
  FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock';
SELECT pass_policy.shmem_unlock_role('regress_lock');
SELECT pass_policy.shmem_reset_failures('regress_lock');
SELECT count(*) AS shmem_locked FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_lock' AND locked_until IS NOT NULL;
SELECT pass_policy.shmem_reload();

-- failed_attempts() : colonnes attendues
SELECT count(*) >= 0 AS callable
  FROM pass_policy.failed_attempts() AS f(role_name, failed_count, first_failure_at,
                                             last_failure_at, locked_until);
