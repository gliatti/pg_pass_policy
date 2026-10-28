--
-- 40_generate — generate_password() (SPEC §4, §8.6)
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_gen LOGIN;

-- Profil large : min_length 8, max_length 512 (bornes absolues de generate_password)
SELECT pass_policy.create_profile('p_gen_wide', '{"min_length": 8, "max_length": 512}') > 0 AS created;

-- Longueurs
SELECT length(pass_policy.generate_password()) AS default_len,
       length(pass_policy.generate_password(12)) AS len_12,
       length(pass_policy.generate_password(128)) AS len_128,
       length(pass_policy.generate_password(8, 'p_gen_wide')) AS len_8,
       length(pass_policy.generate_password(512, 'p_gen_wide')) AS len_512;

-- Bornes absolues : length < 8 et > 512 refusés quel que soit le profil
SELECT ppp_test.try($$SELECT pass_policy.generate_password(7, 'p_gen_wide')$$) <> 'ok' AS len_7_refused,
       ppp_test.try($$SELECT pass_policy.generate_password(0)$$) <> 'ok' AS len_0_refused,
       ppp_test.try($$SELECT pass_policy.generate_password(-1)$$) <> 'ok' AS len_neg_refused,
       ppp_test.try($$SELECT pass_policy.generate_password(513, 'p_gen_wide')$$) <> 'ok' AS len_513_refused;
-- Longueur hors des bornes du profil (default : 12 → 128) : refusée, le
-- mot de passe ne serait pas conforme
SELECT ppp_test.try($$SELECT pass_policy.generate_password(8)$$) <> 'ok' AS below_profile_refused,
       ppp_test.try($$SELECT pass_policy.generate_password(200)$$) <> 'ok' AS above_profile_refused;
-- Profil inconnu refusé
SELECT ppp_test.try($$SELECT pass_policy.generate_password(24, 'no_such_profile')$$) <> 'ok' AS unknown_profile_refused;

-- 200 tirages : classes présentes, aucun caractère ambigu, uniquement imprimables,
-- pas d'espace, tous différents
CREATE TEMP TABLE gen AS
  SELECT g, pass_policy.generate_password() AS pwd
    FROM generate_series(1, 200) g;
SELECT count(*) AS n,
       count(DISTINCT pwd) AS distinct_n,
       bool_and(length(pwd) = 24) AS all_len_24,
       bool_and(pwd ~ '[a-z]') AS has_lower,
       bool_and(pwd ~ '[A-Z]') AS has_upper,
       bool_and(pwd ~ '[0-9]') AS has_digit,
       bool_and(pwd ~ '[^a-zA-Z0-9]') AS has_special,
       bool_and(pwd !~ '[0O1lI|]') AS no_ambiguous,
       bool_and(pwd ~ '^[!-~]+$') AS printable_ascii_no_space
  FROM gen;

-- Deux appels successifs diffèrent
SELECT pass_policy.generate_password() <> pass_policy.generate_password() AS differ;

-- Longueur minimale : les 4 classes tiennent dans 8 caractères
SELECT bool_and(p ~ '[a-z]' AND p ~ '[A-Z]' AND p ~ '[0-9]' AND p ~ '[^a-zA-Z0-9]') AS classes_in_8
  FROM (SELECT pass_policy.generate_password(8, 'p_gen_wide') AS p FROM generate_series(1, 100)) s;

-- Conformité au profil default (check_password = NULL), y compris répétitions
SELECT count(*) AS non_compliant
  FROM gen WHERE pass_policy.check_password('regress_gen', pwd) IS NOT NULL;

-- Conformité à un profil exigeant (minima par classe)
SELECT pass_policy.create_profile('p_gen',
         '{"min_length": 20, "min_lower": 3, "min_upper": 3, "min_digit": 3,
           "min_special": 3, "min_classes": 4}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_gen', 'p_gen');
CREATE TEMP TABLE gen2 AS
  SELECT pass_policy.generate_password(20, 'p_gen') AS pwd
    FROM generate_series(1, 100);
SELECT bool_and(length(regexp_replace(pwd, '[^a-z]', '', 'g')) >= 3) AS lower_ok,
       bool_and(length(regexp_replace(pwd, '[^A-Z]', '', 'g')) >= 3) AS upper_ok,
       bool_and(length(regexp_replace(pwd, '[^0-9]', '', 'g')) >= 3) AS digit_ok,
       bool_and(length(regexp_replace(pwd, '[a-zA-Z0-9]', '', 'g')) >= 3) AS special_ok,
       count(*) FILTER (WHERE pass_policy.check_password('regress_gen', pwd) IS NOT NULL) AS non_compliant
  FROM gen2;

-- Profil irréalisable en pratique : 200 chiffres sur 203 caractères avec
-- max_repeat = 1 (deux chiffres voisins identiques presque à coup sûr) :
-- 22023 (paramètre invalide), et non XX000 (erreur interne)
SELECT pass_policy.create_profile('p_gen_norepeat',
  '{"min_length": 8, "max_length": 512, "min_digit": 200, "max_repeat": 1}') > 0 AS created;
SELECT ppp_test.try($$SELECT pass_policy.generate_password(203, 'p_gen_norepeat')$$) AS infeasible_profile;
SELECT pass_policy.drop_profile('p_gen_norepeat');

-- (vérification 6) _generate_password_for() (utilisée par _rotate_role())
-- connaît le rôle cible : aucun tirage ne contient son nom ni son inverse
-- (PPP-017, toute casse), même pour un nom de 3 lettres. Sur 1000 mots de
-- passe de 512 caractères, environ 16 tirages de generate_password() (qui
-- ignore le rôle) contiennent « abc » ou « cba » : le filtre est donc exercé.
SELECT pass_policy.create_profile('p_gen_name', '{"max_length": 512}') > 0 AS created;
CREATE TEMP TABLE gen_name AS
  SELECT pass_policy._generate_password_for('abc', 512, 'p_gen_name') AS pwd_for,
         pass_policy.generate_password(512, 'p_gen_name') AS pwd_any
    FROM generate_series(1, 1000);
SELECT count(*) FILTER (WHERE lower(pwd_for) ~ '(abc|cba)') AS for_with_name,
       count(*) FILTER (WHERE lower(pwd_any) ~ '(abc|cba)') > 0 AS any_with_name,
       bool_and(length(pwd_for) = 512) AS for_length_ok
  FROM gen_name;
-- même vérification que le hook (PPP-017) sur les tirages filtrés
CREATE ROLE abc LOGIN;
SELECT pass_policy.assign_profile('abc', 'p_gen_name');
SELECT count(*) FILTER (WHERE ppp_test.code(pass_policy.check_password('abc', pwd_for)) = 'PPP-017') AS for_ppp017
  FROM (SELECT pwd_for FROM gen_name LIMIT 200) g;
-- rotation d'un rôle de 3 lettres : jamais refusée par son propre hook
SELECT bool_and(ppp_test.try('SELECT pass_policy.rotate_password(''abc'')') = 'ok') AS rotations_ok
  FROM generate_series(1, 20);
SELECT pass_policy.unassign_profile('abc');
DROP ROLE abc;
SELECT pass_policy.drop_profile('p_gen_name');
DROP TABLE gen_name;

-- generate_password n'écrit rien dans l'audit ni l'historique
SELECT count(*) AS gen_events FROM pass_policy.audit_log
 WHERE role_name = 'regress_gen'
   AND event_type IN ('password_changed', 'password_rotated');

SELECT pass_policy.unassign_profile('regress_gen');
SELECT pass_policy.drop_profile('p_gen');
SELECT pass_policy.drop_profile('p_gen_wide');
DROP TABLE gen, gen2;
