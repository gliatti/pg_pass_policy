--
-- 50_rotation — rotate_password() et expire_password() (SPEC §4, §8.2)
--
-- Le mot de passe renvoyé est capturé directement dans ppp_test.secrets par
-- INSERT … SELECT : il n'est jamais affiché ni présent dans le texte d'une requête.
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_rot LOGIN;
SELECT pass_policy.create_profile('p_rot',
         '{"max_age": "30 days", "grace_period": "7 days", "min_age": "0"}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_rot', 'p_rot');

-- Rotation
INSERT INTO ppp_test.secrets
  SELECT 'rot1', pass_policy.rotate_password('regress_rot');
SELECT length(pwd) AS len,
       pwd !~ '[0O1lI|]' AS no_ambiguous,
       pwd ~ '[a-z]' AND pwd ~ '[A-Z]' AND pwd ~ '[0-9]' AND pwd ~ '[^a-zA-Z0-9]' AS classes_ok
  FROM ppp_test.secrets WHERE label = 'rot1';

-- Le mot de passe est bien en place : il figure dans l'historique (réutilisation refusée)
SELECT ppp_test.code(pass_policy.check_password('regress_rot', pwd)) AS reuse
  FROM ppp_test.secrets WHERE label = 'rot1';
SELECT rolpassword LIKE 'SCRAM-SHA-256$%' AS scram
  FROM pg_authid WHERE rolname = 'regress_rot';

-- role_state mis à jour : changed_at récent, expires_at = +30 j, grace_until = +7 j
SELECT password_changed_at > now() - interval '1 minute' AS changed_recently,
       -- tolérance d'une heure : changements d'heure (PGTZ=PST8PDT dans pg_regress)
       expires_at - password_changed_at BETWEEN interval '29 days 23:00' AND interval '30 days 01:00' AS lifetime_30d,
       grace_until - expires_at BETWEEN interval '6 days 23:00' AND interval '7 days 01:00' AS grace_7d,
       must_change IS NOT TRUE AS not_must_change
  FROM pass_policy.role_state WHERE role_name = 'regress_rot';

-- VALID UNTIL posé = grace_until (changed_at + max_age + grace_period)
SELECT r.rolvaliduntil IS NOT NULL AS valid_until_set,
       abs(extract(epoch FROM r.rolvaliduntil - s.grace_until)) < 2 AS equals_grace_until
  FROM pg_roles r JOIN pass_policy.role_state s ON s.role_name = r.rolname
 WHERE r.rolname = 'regress_rot';

-- Audit password_rotated, sans le mot de passe
SELECT count(*) > 0 AS rotated_audited
  FROM pass_policy.audit_log
 WHERE event_type = 'password_rotated' AND role_name = 'regress_rot';
SELECT count(*) AS audit_with_password
  FROM pass_policy.audit_log a, ppp_test.secrets s
 WHERE s.label = 'rot1' AND strpos(coalesce(a.details::text, ''), s.pwd) > 0;
SELECT actor = session_user AS actor_ok
  FROM pass_policy.audit_log
 WHERE event_type = 'password_rotated' AND role_name = 'regress_rot'
 ORDER BY id DESC LIMIT 1;

-- Longueur personnalisée ; deux rotations donnent deux mots de passe différents
INSERT INTO ppp_test.secrets
  SELECT 'rot2', pass_policy.rotate_password('regress_rot', 32);
SELECT length(pwd) AS len FROM ppp_test.secrets WHERE label = 'rot2';
SELECT (SELECT pwd FROM ppp_test.secrets WHERE label = 'rot1')
    <> (SELECT pwd FROM ppp_test.secrets WHERE label = 'rot2') AS differ;
SELECT count(*) AS history_rows FROM pass_policy.password_history
 WHERE role_name = 'regress_rot';

-- Erreurs
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_no_such_role')$$) <> 'ok' AS unknown_role_refused;
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_rot', 4)$$) <> 'ok' AS too_short_refused;
-- Longueur incompatible avec le profil (min_length 12 par défaut) : refusée
SELECT ppp_test.try($$SELECT pass_policy.rotate_password('regress_rot', 8)$$) <> 'ok' AS below_profile_min_refused;

-- Nom de rôle nécessitant des guillemets (format %I)
CREATE ROLE "regress_Rot quoted" LOGIN;
INSERT INTO ppp_test.secrets
  SELECT 'rot_quoted', pass_policy.rotate_password('regress_Rot quoted');
SELECT rolpassword LIKE 'SCRAM-SHA-256$%' AS scram
  FROM pg_authid WHERE rolname = 'regress_Rot quoted';

-- expire_password : must_change, VALID UNTIL <= now(), statut expired, audit
SELECT pass_policy.expire_password('regress_rot');
SELECT must_change FROM pass_policy.role_state WHERE role_name = 'regress_rot';
SELECT rolvaliduntil <= now() AS expired_now FROM pg_roles WHERE rolname = 'regress_rot';
SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_rot';
SELECT role_name FROM pass_policy.v_expiring WHERE role_name = 'regress_rot';
SELECT count(*) > 0 AS expire_audited
  FROM pass_policy.audit_log
 WHERE event_type = 'password_expired' AND role_name = 'regress_rot';
SELECT ppp_test.try($$SELECT pass_policy.expire_password('regress_no_such_role')$$) <> 'ok' AS unknown_role_refused;

-- Une rotation après expiration remet le rôle en état ok
INSERT INTO ppp_test.secrets
  SELECT 'rot3', pass_policy.rotate_password('regress_rot');
SELECT must_change IS NOT TRUE AS must_change_cleared
  FROM pass_policy.role_state WHERE role_name = 'regress_rot';
SELECT rolvaliduntil > now() + interval '30 days' AS valid_until_reset
  FROM pg_roles WHERE rolname = 'regress_rot';
SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_rot';

SELECT ppp_test.leaks();
