--
-- 80_audit — audit(), purge_audit(), v_recent_audit et absence de secrets (SPEC §3.6, §8)
--
-- LISTEN/NOTIFY n'est pas testé ici : psql affiche les notifications avec le
-- PID du backend émetteur et un horodatage, non reproductibles. Voir
-- test/shell/notify.sh.
--
\set VERBOSITY terse
SET client_min_messages = warning;

-- audit() direct
SELECT pass_policy.audit('maintenance', 'regress_audit', '{"step": "regress", "n": 1}');
SELECT event_type, role_name, actor = session_user AS actor_ok,
       database = current_database() AS database_ok,
       details ->> 'step' AS step, (details ->> 'n')::int AS n,
       event_time <= clock_timestamp() AS time_ok
  FROM pass_policy.audit_log
 WHERE role_name = 'regress_audit';
-- details par défaut = '{}'
SELECT pass_policy.audit('maintenance', 'regress_audit2');
SELECT details FROM pass_policy.audit_log WHERE role_name = 'regress_audit2';
-- role_name NULL autorisé (événements globaux)
SELECT ppp_test.try($$SELECT pass_policy.audit('maintenance', NULL, '{"global": true}')$$) AS null_role;
-- Type d'événement hors de la liste SPEC §3.6 refusé
SELECT ppp_test.try($$SELECT pass_policy.audit('no_such_event', 'regress_audit')$$) <> 'ok' AS bad_event_refused;

-- v_recent_audit : au plus 1000 lignes, contient le dernier événement
SELECT count(*) <= 1000 AS bounded FROM pass_policy.v_recent_audit;
SELECT count(*) > 0 AS has_recent FROM pass_policy.v_recent_audit
 WHERE role_name = 'regress_audit2';
INSERT INTO pass_policy.audit_log (event_type, role_name, details)
  SELECT 'maintenance', 'regress_audit_bulk', jsonb_build_object('i', g)
    FROM generate_series(1, 1100) g;
SELECT count(*) AS recent_rows FROM pass_policy.v_recent_audit;
-- Les 1000 plus récents : la ligne regress_audit2, plus ancienne que le lot, n'y est plus
SELECT count(*) AS old_row_visible FROM pass_policy.v_recent_audit
 WHERE role_name = 'regress_audit2';

-- purge_audit : seules les lignes plus anciennes que le seuil sont supprimées
UPDATE pass_policy.audit_log
   SET event_time = now() - interval '400 days'
 WHERE role_name = 'regress_audit_bulk';
UPDATE pass_policy.audit_log
   SET event_time = now() - interval '10 days'
 WHERE role_name = 'regress_audit';
SELECT pass_policy.purge_audit() AS purged_default;
SELECT count(*) AS bulk_left FROM pass_policy.audit_log WHERE role_name = 'regress_audit_bulk';
SELECT pass_policy.purge_audit(interval '5 days') AS purged_5_days;
SELECT count(*) AS audit_left FROM pass_policy.audit_log WHERE role_name = 'regress_audit';
SELECT pass_policy.purge_audit(interval '5 days') AS purged_again;

-- Tous les types d'événements présents appartiennent à la liste SPEC §3.6
SELECT DISTINCT event_type FROM pass_policy.audit_log
 WHERE event_type NOT IN ('password_changed', 'password_rejected', 'auth_failed',
                          'role_locked', 'role_unlocked', 'expiry_warning',
                          'password_expired', 'password_rotated', 'profile_assigned',
                          'profile_changed', 'pair_switched', 'valid_until_synced',
                          'maintenance');

-- Aucun secret dans l'audit : ni commande ALTER ROLE … PASSWORD, ni mot de passe
-- de test, ni vérificateur
SELECT count(*) AS rows_with_password_cmd FROM pass_policy.audit_log
 WHERE details::text LIKE '%PASSWORD %' OR details::text ILIKE '%alter role%';
SELECT count(*) AS known_secrets FROM ppp_test.secrets;
SELECT ppp_test.leaks();
-- L'historique n'est jamais exposé dans l'audit (aucun vérificateur connu)
SELECT count(*) AS verifiers_in_audit
  FROM pass_policy.audit_log a, pass_policy.password_history h
 WHERE strpos(a.details::text, h.verifier) > 0;
