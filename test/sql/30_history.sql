--
-- 30_history — historique anti-réutilisation (PPP-031) et min_age (PPP-030), SPEC §3.4, §6.2
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_hist LOGIN;
SELECT pass_policy.create_profile('p_hist',
         '{"history_count": 3, "history_days": 365, "min_age": "0"}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_hist', 'p_hist');

INSERT INTO ppp_test.secrets VALUES
  ('hist1', 'History-One#2024'),
  ('hist2', 'History-Two#2024'),
  ('hist3', 'History-Three#2024'),
  ('hist4', 'History-Four#2024'),
  ('hist5', 'History-Five#2024');

-- Quatre changements successifs
ALTER ROLE regress_hist PASSWORD 'History-One#2024';
ALTER ROLE regress_hist PASSWORD 'History-Two#2024';
ALTER ROLE regress_hist PASSWORD 'History-Three#2024';
ALTER ROLE regress_hist PASSWORD 'History-Four#2024';

-- Historique tronqué à history_count, uniquement des vérificateurs SCRAM
SELECT count(*) AS history_rows,
       bool_and(verifier LIKE 'SCRAM-SHA-256$%') AS all_scram,
       count(DISTINCT verifier) AS distinct_verifiers
  FROM pass_policy.password_history WHERE role_name = 'regress_hist';
-- Le dernier vérificateur de l'historique correspond au mot de passe actuel :
-- même schéma SCRAM (le sel peut différer de pg_authid, donc pas d'égalité stricte)
SELECT count(*) AS changed_events FROM pass_policy.audit_log
 WHERE role_name = 'regress_hist' AND event_type = 'password_changed';

-- Réutilisation : les 3 derniers sont refusés, le 1er (sorti de l'historique) est accepté
SELECT ppp_test.code(pass_policy.check_password('regress_hist', 'History-Four#2024')) AS reuse_4,
       ppp_test.code(pass_policy.check_password('regress_hist', 'History-Three#2024')) AS reuse_3,
       ppp_test.code(pass_policy.check_password('regress_hist', 'History-Two#2024')) AS reuse_2,
       ppp_test.code(pass_policy.check_password('regress_hist', 'History-One#2024')) AS reuse_1;
ALTER ROLE regress_hist PASSWORD 'History-Four#2024';
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'History-Two#2024'$$) AS reuse_2;
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'History-One#2024'$$) AS reuse_1;
-- Maintenant : historique = Three, Four, One → Two redevient utilisable
SELECT ppp_test.code(pass_policy.check_password('regress_hist', 'History-Two#2024')) AS reuse_2,
       ppp_test.code(pass_policy.check_password('regress_hist', 'History-One#2024')) AS reuse_1;
SELECT count(*) AS history_rows FROM pass_policy.password_history
 WHERE role_name = 'regress_hist';

-- history_count = 0 : historique désactivé, réutilisation permise
SELECT pass_policy.alter_profile('p_hist', '{"history_count": 0}');
SELECT ppp_test.code(pass_policy.check_password('regress_hist', 'History-One#2024')) AS reuse_disabled;
SELECT pass_policy.alter_profile('p_hist', '{"history_count": 3}');

-- history_days : une entrée plus ancienne que history_days n'est plus comparée
UPDATE pass_policy.password_history
   SET changed_at = now() - interval '400 days'
 WHERE role_name = 'regress_hist'
   AND changed_at = (SELECT min(changed_at) FROM pass_policy.password_history
                      WHERE role_name = 'regress_hist');
SELECT ppp_test.code(pass_policy.check_password('regress_hist', 'History-Three#2024')) AS old_entry_ignored;

-- min_age : un non-superutilisateur ne peut pas changer deux fois dans l'intervalle.
-- SET SESSION AUTHORIZATION : session_user et current_user deviennent regress_hist.
SELECT pass_policy.alter_profile('p_hist', '{"min_age": "1 hour"}');
SET SESSION AUTHORIZATION regress_hist;
SELECT current_user, session_user;
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'History-Five#2024'$$) AS min_age_user;
ALTER ROLE regress_hist PASSWORD 'History-Five#2024';
RESET SESSION AUTHORIZATION;
SELECT current_user = session_user AS back_to_superuser;
-- check_password appelé par un superutilisateur : min_age ne s'applique pas
SELECT ppp_test.code(pass_policy.check_password('regress_hist', 'History-Five#2024')) AS min_age_superuser_check;
-- Le superutilisateur contourne min_age
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'History-Five#2024'$$) AS min_age_superuser;

-- min_age écoulé : le rôle peut changer lui-même son mot de passe
UPDATE pass_policy.role_state
   SET password_changed_at = now() - interval '2 hours'
 WHERE role_name = 'regress_hist';
SET SESSION AUTHORIZATION regress_hist;
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'History-Six#2024x'$$) AS min_age_elapsed;
RESET SESSION AUTHORIZATION;
INSERT INTO ppp_test.secrets VALUES ('hist6', 'History-Six#2024x');
-- … et la complexité s'applique aussi au rôle lui-même
SET SESSION AUTHORIZATION regress_hist;
SELECT ppp_test.try($$ALTER ROLE regress_hist PASSWORD 'weak'$$) AS self_weak;
RESET SESSION AUTHORIZATION;

-- Jamais de clair : aucun vérificateur ne contient un mot de passe de test
SELECT bool_and(verifier LIKE 'SCRAM-SHA-256$%') AS all_scram,
       count(*) FILTER (WHERE verifier !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$') AS malformed
  FROM pass_policy.password_history;
SELECT ppp_test.leaks();

SELECT pass_policy.unassign_profile('regress_hist');
SELECT pass_policy.drop_profile('p_hist');
