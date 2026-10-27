--
-- 10_profile — profils : create/alter/drop/assign/unassign/effective_profile (SPEC §3.1, §3.2, §4)
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_prof LOGIN;
CREATE ROLE regress_prof2 LOGIN;

-- Création avec paramètres jsonb ; renvoie l'identifiant
SELECT pass_policy.create_profile('p_strict',
         '{"min_length": 16, "min_classes": 4, "max_age": "30 days",
           "lock_duration": null, "reject_username": true}') > 0 AS created;

-- Création sans paramètre : valeurs par défaut de la table
SELECT pass_policy.create_profile('p_plain') > 0 AS created;

SELECT name, min_length, min_classes, max_age, lock_duration, history_count
  FROM pass_policy.profile
 WHERE name IN ('p_strict', 'p_plain') ORDER BY name;

-- Doublon refusé
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_plain')$$) <> 'ok' AS duplicate_refused;

-- Clé inconnue dans le jsonb : refus explicite
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"no_such_key": 1}')$$) <> 'ok' AS unknown_key_refused;
SELECT count(*) AS p_bad_rows FROM pass_policy.profile WHERE name = 'p_bad';
-- Les colonnes techniques ne sont pas modifiables via settings
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"profile_id": 999}')$$) <> 'ok' AS profile_id_refused;
-- Valeur invalide (type)
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_length": "abc"}')$$) <> 'ok' AS bad_value_refused;

-- alter_profile
SELECT pass_policy.alter_profile('p_plain', '{"min_length": 14, "max_age": null}');
SELECT name, min_length, max_age, updated_at >= created_at AS updated
  FROM pass_policy.profile WHERE name = 'p_plain';
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"bogus": true}')$$) <> 'ok' AS unknown_key_refused;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('no_such_profile', '{"min_length": 14}')$$) <> 'ok' AS unknown_profile_refused;
-- Injection dans le nom de clé : refusée (clé inconnue), aucun effet
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"min_length = 1; DROP TABLE pass_policy.profile; --": 1}')$$) <> 'ok' AS injection_refused;
SELECT count(*) AS profile_table_ok FROM pass_policy.profile WHERE name = 'p_plain';

-- effective_profile : sans affectation → default
SELECT name FROM pass_policy.effective_profile('regress_prof');
-- rôle inexistant → default également
SELECT name FROM pass_policy.effective_profile('regress_no_such_role');

-- assign_profile
SELECT pass_policy.assign_profile('regress_prof', 'p_strict');
SELECT name FROM pass_policy.effective_profile('regress_prof');
SELECT rp.role_name, p.name, rp.role_oid = 'regress_prof'::regrole::oid AS oid_ok,
       rp.assigned_by = session_user AS assigned_by_ok
  FROM pass_policy.role_profile rp JOIN pass_policy.profile p USING (profile_id)
 WHERE rp.role_name = 'regress_prof';
SELECT count(*) > 0 AS audited
  FROM pass_policy.audit_log
 WHERE event_type = 'profile_assigned' AND role_name = 'regress_prof';

-- Réaffectation : une seule ligne par rôle
SELECT pass_policy.assign_profile('regress_prof', 'p_plain');
SELECT count(*) AS rows, min(p.name) AS profile
  FROM pass_policy.role_profile rp JOIN pass_policy.profile p USING (profile_id)
 WHERE rp.role_name = 'regress_prof';

-- Erreurs d'affectation
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_prof', 'no_such_profile')$$) <> 'ok' AS unknown_profile_refused;
SELECT ppp_test.try($$SELECT pass_policy.assign_profile('regress_no_such_role', 'p_plain')$$) <> 'ok' AS unknown_role_refused;

-- drop_profile : refuse default et un profil assigné
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('default')$$) <> 'ok' AS drop_default_refused;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('p_plain')$$) <> 'ok' AS drop_assigned_refused;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('no_such_profile')$$) <> 'ok' AS drop_unknown_refused;
SELECT count(*) AS still_there FROM pass_policy.profile WHERE name IN ('default', 'p_plain');

-- unassign_profile, puis drop possible
SELECT pass_policy.unassign_profile('regress_prof');
SELECT count(*) AS rows FROM pass_policy.role_profile WHERE role_name = 'regress_prof';
SELECT name FROM pass_policy.effective_profile('regress_prof');
SELECT pass_policy.drop_profile('p_plain');
SELECT count(*) AS dropped FROM pass_policy.profile WHERE name = 'p_plain';

-- p_strict reste disponible pour un second rôle, puis nettoyage
SELECT pass_policy.assign_profile('regress_prof2', 'p_strict');
SELECT name, min_length FROM pass_policy.effective_profile('regress_prof2');
SELECT pass_policy.unassign_profile('regress_prof2');
SELECT pass_policy.drop_profile('p_strict');

-- Nom de profil avec guillemets : refusé proprement (contrainte sur le nom)
-- ou accepté et manipulable ; dans les deux cas aucune erreur de syntaxe SQL
-- (42601) ne doit remonter, ce qui trahirait une concaténation non protégée.
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p "quoted''name"', '{"min_length": 20}')$$) NOT LIKE '42601%' AS no_syntax_error;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('p "quoted''name"')$$) NOT LIKE '42601%' AS no_syntax_error;

SELECT ppp_test.leaks();
