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

-- (vérification) Bornes absolues alignées sur generate_password() (8 à 512,
-- PPP_GEN_MAX_LENGTH) et somme des minima de classes <= max_length : 23514
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_length": 513, "max_length": 512}')$$) AS min_length_over_512;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"max_length": 513}')$$) AS max_length_over_512;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_length": 512, "max_length": 512}')$$) AS length_512_ok;
SELECT pass_policy.drop_profile('p_bad');
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_digit": 128}')$$) AS classes_over_max_length;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_lower": 2000000000, "min_upper": 2000000000}')$$) AS classes_sum_no_overflow;
-- (vérification 2) profile_classes_fit suit le besoin réel du générateur
-- (_generator_minimum : une minuscule, une majuscule et un chiffre au moins,
-- plus un spécial si min_classes l'exige), pas la simple somme des minima
SELECT pass_policy._generator_minimum(0, 0, 30, 0, 3) AS gen_min_digit30,
       pass_policy._generator_minimum(0, 0, 30, 0, 4) AS gen_min_classes4,
       pass_policy._generator_minimum(2, 0, 0, 3, 4) AS gen_min_special,
       pass_policy._generator_minimum(2000000000, 2000000000, 0, 0, 0) AS gen_min_capped,
       pass_policy._max_generated_length() AS max_generated;
-- somme 30 <= 31, mais le générateur en demande 32 : refusé
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_lower": 0, "min_upper": 0, "min_digit": 30, "min_special": 0, "min_classes": 3, "max_length": 31}')$$) AS gen_min_over_max;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_lower": 0, "min_upper": 0, "min_digit": 30, "min_special": 0, "min_classes": 4, "max_length": 32}')$$) AS gen_min_classes_over_max;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"min_lower": 0, "min_upper": 0, "min_digit": 30, "min_special": 0, "min_classes": 3, "max_length": 32}')$$) AS gen_min_fits;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_bad', '{"min_classes": 4}')$$) AS alter_gen_min_over_max;
SELECT pass_policy.drop_profile('p_bad');
SELECT count(*) AS p_bad_rows FROM pass_policy.profile WHERE name = 'p_bad';

-- alter_profile
SELECT pass_policy.alter_profile('p_plain', '{"min_length": 14, "max_age": null}');
SELECT name, min_length, max_age, updated_at >= created_at AS updated
  FROM pass_policy.profile WHERE name = 'p_plain';
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"bogus": true}')$$) <> 'ok' AS unknown_key_refused;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('no_such_profile', '{"min_length": 14}')$$) <> 'ok' AS unknown_profile_refused;
-- Injection dans le nom de clé : refusée (clé inconnue), aucun effet
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"min_length = 1; DROP TABLE pass_policy.profile; --": 1}')$$) <> 'ok' AS injection_refused;
SELECT count(*) AS profile_table_ok FROM pass_policy.profile WHERE name = 'p_plain';

-- Durées sous la seconde refusées : la mémoire partagée les reçoit en secondes
-- entières (worker.c), un lock_duration de 0,4 s y deviendrait 0 (verrou déjà
-- expiré, donc jamais effectif) et un failure_window de 0,4 s « pas de fenêtre »
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"lock_duration": "0.4 seconds"}')$$) AS lock_subsecond;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"lock_duration": "0 seconds"}')$$) AS lock_zero;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"failure_window": "0.4 seconds"}')$$) AS window_subsecond;
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p_bad', '{"lock_duration": "500 milliseconds"}')$$) AS create_lock_subsecond;
-- 1 seconde, et failure_window = 0 (pas de fenêtre) restent acceptés
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"lock_duration": "1 second", "failure_window": "1 second"}')$$) AS one_second;
SELECT ppp_test.try($$SELECT pass_policy.alter_profile('p_plain', '{"failure_window": "0"}')$$) AS window_zero;
SELECT lock_duration, failure_window FROM pass_policy.profile WHERE name = 'p_plain';
SELECT pass_policy.alter_profile('p_plain', '{"lock_duration": "30 minutes", "failure_window": "15 minutes"}');

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

-- (clôture) drop_profile() ne compte pas les lignes role_profile des rôles
-- supprimés (purgées sur place) : le profil d'un rôle disparu se supprime
CREATE ROLE regress_ghost LOGIN;
SELECT pass_policy.create_profile('p_ghost', '{}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_ghost', 'p_ghost');
DROP ROLE regress_ghost;
SELECT count(*) AS stale_rows FROM pass_policy.role_profile WHERE role_name = 'regress_ghost';
SELECT pass_policy.drop_profile('p_ghost');
SELECT count(*) AS stale_rows_after FROM pass_policy.role_profile WHERE role_name = 'regress_ghost';
SELECT count(*) AS dropped FROM pass_policy.profile WHERE name = 'p_ghost';

-- Nom de profil avec guillemets : refusé proprement (contrainte sur le nom)
-- ou accepté et manipulable ; dans les deux cas aucune erreur de syntaxe SQL
-- (42601) ne doit remonter, ce qui trahirait une concaténation non protégée.
SELECT ppp_test.try($$SELECT pass_policy.create_profile('p "quoted''name"', '{"min_length": 20}')$$) NOT LIKE '42601%' AS no_syntax_error;
SELECT ppp_test.try($$SELECT pass_policy.drop_profile('p "quoted''name"')$$) NOT LIKE '42601%' AS no_syntax_error;

SELECT ppp_test.leaks();
