--
-- 20_complexity — règles de complexité PPP-001, PPP-010 → PPP-020 (SPEC §6.2)
--
-- Le contrôle est fait à la fois via check_password() (sans effet de bord, on
-- n'affiche que le code PPP-xxx) et via de vrais CREATE/ALTER ROLE (via
-- ppp_test.try(), qui renvoie 'SQLSTATE PPP-xxx'). Quelques ALTER ROLE sont
-- exécutés directement pour figer le format du message (VERBOSITY terse).
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_cplx LOGIN;

-- Mot du dictionnaire personnalisé (stocké en minuscules)
SELECT pass_policy.load_dictionary(ARRAY['Correct-Horse9']) AS loaded;
SELECT word FROM pass_policy.dictionary WHERE word = 'correct-horse9';
-- Le hook ne compare que le SHA-256 du mot de passe en minuscules à la colonne
-- générée word_sha256 (octets bruts du mot, encodage du serveur, y compris
-- pour une barre oblique inverse)
SELECT pass_policy.load_dictionary(ARRAY['Back\Slash-Word9']) AS loaded_backslash;
SELECT bool_and(word_sha256 = sha256(convert_to(word, current_setting('server_encoding')))) AS digests_ok,
       count(DISTINCT word_sha256) = count(*) AS digests_unique
  FROM pass_policy.dictionary;
-- (vérification 5) INSERT direct : le trigger ignore un mot NULL (comme un
-- mot vide) au lieu de faire échouer toute l'instruction
WITH ins AS (INSERT INTO pass_policy.dictionary (word)
             VALUES (NULL), ('  '), ('Null-Word-Test9') RETURNING word)
SELECT array_agg(word) AS inserted FROM ins;
DELETE FROM pass_policy.dictionary WHERE word = 'null-word-test9';

-- Audit avant les appels à check_password() (doit rester inchangé)
CREATE TEMP TABLE audit_before AS
  SELECT count(*) AS n FROM pass_policy.audit_log
   WHERE role_name = 'regress_cplx'
     AND event_type IN ('password_changed', 'password_rejected');
CREATE TEMP TABLE history_before AS
  SELECT count(*) AS n FROM pass_policy.password_history
   WHERE role_name = 'regress_cplx';

-- Cas de test : (attendu, mot de passe). Le mot de passe n'est jamais affiché.
CREATE TEMP TABLE cases (id int, expected text, pwd text);
INSERT INTO cases VALUES
  ( 1, 'PPP-010', 'Ab9!xyz'),                   -- 7 caractères < 12
  ( 2, 'PPP-010', 'abc'),                       -- la longueur passe avant les classes
  ( 3, 'PPP-011', repeat('Ab9!', 33)),          -- 132 caractères > 128
  ( 4, 'PPP-012', 'abcdefghijkmnp'),            -- une seule classe
  ( 5, 'PPP-012', 'abcdefghij2345'),            -- deux classes
  ( 6, 'PPP-013', 'ABCDEFGH2345#$'),            -- 3 classes, aucune minuscule
  ( 7, 'PPP-014', 'abcdefgh2345#$'),            -- aucune majuscule
  ( 8, 'PPP-015', 'abcdefGHIJK#$%'),            -- aucun chiffre
  ( 9, 'PPP-016', 'abcdefGHIJ2345'),            -- aucun caractère spécial
  (10, 'PPP-017', 'Zz9!regress_cplx'),          -- contient le nom du rôle
  (11, 'PPP-017', 'Zz9!REGRESS_CPLX'),          -- insensible à la casse
  (12, 'PPP-017', 'Zz9!xlpc_sserger'),          -- nom inversé
  (13, 'PPP-018', 'CORRECT-horse9'),            -- dictionnaire, insensible à la casse
  (14, 'PPP-019', 'Abcd9!xxxxyz'),              -- 4 caractères identiques > max_repeat 3
  (15, 'PPP-020', ' Abcdef9!ghij'),             -- espace en tête
  (16, 'PPP-020', 'Abcdef9!ghij '),             -- espace en fin
  (17, 'PPP-020', 'Abcdef9!' || chr(9) || 'ghij'),  -- tabulation
  (18, 'PPP-020', 'Abcdef9!' || chr(1) || 'ghij'),  -- caractère de contrôle
  (19, 'PPP-001', 'md5d45b8ce98dfa91f53bed90f775e1cb94'),
  (20, 'PPP-001', 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw='),
  (21, NULL, 'Tr0ub4dour&Horse-42'),            -- conforme
  (22, NULL, 'Abcdefg9!xyz'),                   -- exactement 12 caractères
  (23, NULL, 'Abcd9!xxxyz12'),                  -- exactement 3 répétitions
  (24, NULL, rpad('Ab9!', 128, 'xyZ7')),        -- exactement 128 caractères
  (25, NULL, 'Mid space 9!Ok'),                 -- espace interne autorisé
  (26, 'PPP-018', 'BACK\slash-WORD9');            -- dictionnaire, mot avec « \ »
-- (les vérificateurs pré-hachés ne sont pas des secrets : exclus)
INSERT INTO ppp_test.secrets SELECT 'cplx' || id, pwd FROM cases
 WHERE expected IS DISTINCT FROM 'PPP-001';

-- check_password : code attendu = code obtenu
SELECT id, expected, ppp_test.code(pass_policy.check_password('regress_cplx', pwd)) AS got
  FROM cases ORDER BY id;
-- Les motifs de refus ne contiennent jamais le mot de passe
SELECT count(*) AS reasons_with_password
  FROM cases
 WHERE strpos(coalesce(pass_policy.check_password('regress_cplx', pwd), ''), pwd) > 0;
-- check_password est sans effet de bord
SELECT (SELECT count(*) FROM pass_policy.audit_log
         WHERE role_name = 'regress_cplx'
           AND event_type IN ('password_changed', 'password_rejected'))
       = (SELECT n FROM audit_before) AS audit_unchanged,
       (SELECT count(*) FROM pass_policy.password_history
         WHERE role_name = 'regress_cplx')
       = (SELECT n FROM history_before) AS history_unchanged;

-- Vrais ALTER ROLE : refusés avec SQLSTATE 28P01 (invalid_password) et le même code
SELECT id, expected,
       ppp_test.try(format('ALTER ROLE regress_cplx PASSWORD %L', pwd)) AS got
  FROM cases WHERE expected IS NOT NULL ORDER BY id;

-- Format du message (préfixe stable PPP-xxx, aucun mot de passe)
ALTER ROLE regress_cplx PASSWORD 'Ab9!xyz';
ALTER ROLE regress_cplx PASSWORD 'abcdefghijkmnp';
CREATE ROLE regress_cplx_bad LOGIN PASSWORD 'abcdefghijkmnp';
SELECT count(*) AS created FROM pg_roles WHERE rolname = 'regress_cplx_bad';

-- Aucun changement n'a été enregistré pour les refus
SELECT count(*) AS history_rows FROM pass_policy.password_history
 WHERE role_name = 'regress_cplx';

-- Mots de passe conformes acceptés (superutilisateur : min_age ne s'applique pas)
SELECT id, ppp_test.try(format('ALTER ROLE regress_cplx PASSWORD %L', pwd)) AS got
  FROM cases WHERE expected IS NULL ORDER BY id;
SELECT count(*) AS history_rows,
       bool_and(verifier LIKE 'SCRAM-SHA-256$%') AS all_scram,
       bool_and(role_oid = 'regress_cplx'::regrole::oid) AS oid_ok
  FROM pass_policy.password_history WHERE role_name = 'regress_cplx';
SELECT count(*) AS changed_events FROM pass_policy.audit_log
 WHERE role_name = 'regress_cplx' AND event_type = 'password_changed';
SELECT password_changed_at IS NOT NULL AS changed_known
  FROM pass_policy.role_state WHERE role_name = 'regress_cplx';

-- CREATE ROLE … PASSWORD conforme : historique et état créés pour le nouvel OID
CREATE ROLE regress_cplx_new LOGIN PASSWORD 'Fresh-Start#2024x';
INSERT INTO ppp_test.secrets VALUES ('cplx_new', 'Fresh-Start#2024x');
-- Au moment du hook, le rôle n'existe pas encore (pas d'OID) : l'historique
-- est enregistré par nom ; l'OID et role_state peuvent n'être complétés qu'au
-- passage suivant de run_maintenance(). On vérifie l'état après maintenance.
SELECT count(*) AS history_rows
  FROM pass_policy.password_history WHERE role_name = 'regress_cplx_new';
SELECT count(*) >= 0 AS maintenance_ran FROM pass_policy.run_maintenance();
SELECT count(*) AS history_rows,
       bool_and(h.role_oid = r.oid) AS oid_ok
  FROM pass_policy.password_history h JOIN pg_roles r ON r.rolname = h.role_name
 WHERE h.role_name = 'regress_cplx_new';
SELECT s.role_oid = 'regress_cplx_new'::regrole::oid AS oid_ok,
       s.password_changed_at IS NOT NULL AS changed_known
  FROM pass_policy.role_state s WHERE s.role_name = 'regress_cplx_new';

-- Profil personnalisé : règles assouplies et appliquées au rôle affecté
SELECT pass_policy.create_profile('p_cplx_soft',
         '{"min_length": 8, "min_classes": 2, "min_upper": 0, "min_special": 0,
           "min_digit": 0, "max_repeat": 0, "reject_username": false,
           "reject_dictionary": false, "min_age": "0"}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_cplx', 'p_cplx_soft');
SELECT ppp_test.code(pass_policy.check_password('regress_cplx', 'abcdefgh')) AS one_class,
       ppp_test.code(pass_policy.check_password('regress_cplx', 'abcdefg8')) AS two_classes,
       ppp_test.code(pass_policy.check_password('regress_cplx', 'regress_cplx8')) AS username_allowed,
       ppp_test.code(pass_policy.check_password('regress_cplx', 'aaaaaaaa8')) AS repeat_allowed,
       ppp_test.code(pass_policy.check_password('regress_cplx', 'abcdef7')) AS too_short;
SELECT pass_policy.unassign_profile('regress_cplx');

-- Vérificateurs pré-hachés acceptés si reject_prehashed = false (SCRAM tel quel)
CREATE ROLE regress_prehash LOGIN;
SELECT pass_policy.create_profile('p_prehash', '{"reject_prehashed": false}') > 0 AS created;
SELECT pass_policy.assign_profile('regress_prehash', 'p_prehash');
SELECT ppp_test.try($$ALTER ROLE regress_prehash PASSWORD 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw='$$) AS scram_prehashed;
SELECT verifier = 'SCRAM-SHA-256$4096:haqxM21W2X4JN2z5mNIhgQ==$6wQyAb1jy/PwU6taBTaUoM8DCeQcK961IfQ80mS4Iwk=:nYBdZfaOxx6o2q0ioUkoxD3rmW1Nff4RWaNnPPYCZiw=' AS stored_as_is
  FROM pass_policy.password_history WHERE role_name = 'regress_prehash';
-- MD5 pré-haché : refusé par require_scram (code non spécifié dans SPEC)
SET client_min_messages = error;
SELECT ppp_test.try($$ALTER ROLE regress_prehash PASSWORD 'md5d45b8ce98dfa91f53bed90f775e1cb94'$$) <> 'ok' AS md5_refused;
-- password_encryption = md5 : refusé par require_scram
SET password_encryption = 'md5';
SELECT ppp_test.try($$ALTER ROLE regress_prehash PASSWORD 'Tr0ub4dour&Horse-42'$$) <> 'ok' AS md5_encryption_refused;
RESET password_encryption;
SET client_min_messages = warning;
SELECT rolpassword LIKE 'SCRAM-SHA-256$%' AS still_scram FROM pg_authid WHERE rolname = 'regress_prehash';

-- enforce_database = on : hors de pg_pass_policy.database, le changement est refusé
SELECT current_database() AS regress_db \gset
\c postgres
\set VERBOSITY terse
SET client_min_messages = warning;
ALTER ROLE regress_cplx PASSWORD 'Other-Database#42';
-- les autres ALTER ROLE ne sont pas concernés
ALTER ROLE regress_cplx CONNECTION LIMIT 5;
ALTER ROLE regress_cplx CONNECTION LIMIT -1;
\c :regress_db
\set VERBOSITY terse
SET client_min_messages = warning;
INSERT INTO ppp_test.secrets VALUES ('otherdb', 'Other-Database#42');
SELECT count(*) AS history_rows FROM pass_policy.password_history
 WHERE role_name = 'regress_cplx';

SELECT ppp_test.leaks();
