--
-- 95_parity — check_password() répond ce que le hook répondrait au même
-- appelant, dans les deux sens (NULL ⇔ ALTER ROLE accepté, code ⇔ même
-- refus), SPEC §4 et §6.2, vérification 9. Seule exception, testée dans
-- 20_complexity : superuser_bypass, ignoré par check_password().
--
\set VERBOSITY terse
SET client_min_messages = warning;

-- Réponse de check_password() puis du hook (ALTER ROLE … PASSWORD, appliqué
-- s'il est accepté), pour l'utilisateur courant
CREATE FUNCTION ppp_test.parity(r text, pwd text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE fn text;
BEGIN
  fn := coalesce(ppp_test.code(pass_policy.check_password(r, pwd)), 'ok');
  RETURN fn || ' | ' || ppp_test.try(format('ALTER ROLE %I PASSWORD %L', r, pwd));
END $$;
GRANT EXECUTE ON FUNCTION ppp_test.parity(text, text) TO PUBLIC;

INSERT INTO ppp_test.secrets VALUES
  ('par1', 'Parity-One#2024ab'), ('par2', 'Parity-Two#2024ab'),
  ('par3', 'Parity-Three#2024a'), ('par4', 'Parity-Four#2024ab');

-- pass_policy_admin : droit d'exécuter check_password() (pas superutilisateur)
CREATE ROLE regress_parity LOGIN IN ROLE pass_policy_admin;
SELECT pass_policy.create_profile('p_parity',
         '{"history_count": 3, "history_days": 365, "min_age": "1 hour"}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_parity', 'p_parity');
ALTER ROLE regress_parity PASSWORD 'Parity-One#2024ab';

-- Superutilisateur, juste après un changement : min_age ignoré par les deux
SELECT ppp_test.parity('regress_parity', 'Parity-Two#2024ab') AS super_min_age;
-- … la réutilisation et la complexité restent refusées par les deux
SELECT ppp_test.parity('regress_parity', 'Parity-One#2024ab') AS super_reuse;
SELECT ppp_test.parity('regress_parity', 'weak') AS super_weak;

-- Le rôle lui-même, juste après un changement : min_age refusé par les deux
SET SESSION AUTHORIZATION regress_parity;
SELECT ppp_test.parity('regress_parity', 'Parity-Three#2024a') AS self_min_age;
SELECT ppp_test.parity('regress_parity', 'weak') AS self_weak;
RESET SESSION AUTHORIZATION;

-- min_age écoulé : accepté par les deux, puis réutilisation refusée par les deux
UPDATE pass_policy.role_state
   SET password_changed_at = now() - interval '2 hours'
 WHERE role_name = 'regress_parity';
SET SESSION AUTHORIZATION regress_parity;
SELECT ppp_test.parity('regress_parity', 'Parity-Three#2024a') AS self_min_age_elapsed;
RESET SESSION AUTHORIZATION;
UPDATE pass_policy.role_state
   SET password_changed_at = now() - interval '2 hours'
 WHERE role_name = 'regress_parity';
SET SESSION AUTHORIZATION regress_parity;
SELECT ppp_test.parity('regress_parity', 'Parity-Two#2024ab') AS self_reuse;
SELECT ppp_test.parity('regress_parity', 'Parity-Four#2024ab') AS self_ok;
RESET SESSION AUTHORIZATION;

DROP FUNCTION ppp_test.parity(text, text);
SELECT pass_policy.unassign_profile('regress_parity');
SELECT pass_policy.drop_profile('p_parity');
DROP ROLE regress_parity;

-- Secrets de ce test vérifiés puis retirés (vérification 10) : les tests
-- suivants ne dépendent pas des lignes par1..par4
SELECT ppp_test.leaks();
DELETE FROM ppp_test.secrets WHERE label IN ('par1', 'par2', 'par3', 'par4');
