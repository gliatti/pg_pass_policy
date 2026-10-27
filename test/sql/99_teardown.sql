--
-- 99_teardown — suppression de l'extension et des rôles de test
--
-- Les rôles pass_policy_admin et pass_policy_viewer sont des objets globaux
-- (pg_authid) : DROP EXTENSION ne les supprime pas. Ils restent en place pour
-- une éventuelle réinstallation (CREATE EXTENSION doit donc tolérer leur
-- présence).
--
\set VERBOSITY terse
SET client_min_messages = warning;

-- Dernière vérification globale : aucun secret dans l'audit ni l'historique
SELECT ppp_test.leaks();

DROP SCHEMA ppp_test CASCADE;
DROP EXTENSION pg_pass_policy;

SELECT count(*) AS ext FROM pg_extension WHERE extname = 'pg_pass_policy';
SELECT count(*) AS schema FROM pg_namespace WHERE nspname = 'pass_policy';
SELECT rolname FROM pg_roles
 WHERE rolname IN ('pass_policy_admin', 'pass_policy_viewer') ORDER BY 1;

-- Après DROP EXTENSION, la bibliothèque reste chargée (shared_preload_libraries) :
-- les commandes sans mot de passe ne doivent pas être gênées.
ALTER ROLE regress_user CONNECTION LIMIT 1;

DO $$
DECLARE r text;
BEGIN
  FOR r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'regress\_%' ORDER BY rolname
  LOOP
    EXECUTE format('DROP ROLE %I', r);
  END LOOP;
END $$;
SELECT count(*) AS regress_roles_left FROM pg_roles WHERE rolname LIKE 'regress\_%';

-- Réinstallation possible (rôles déjà présents), puis suppression
CREATE EXTENSION pg_pass_policy;
SELECT count(*) AS reinstalled FROM pass_policy.profile WHERE name = 'default';
DROP EXTENSION pg_pass_policy;
