--
-- 55_pair — rotation sans coupure par paire de rôles (SPEC §3.7, §4)
--
\set VERBOSITY terse
SET client_min_messages = warning;

CREATE ROLE regress_app_grp NOLOGIN;

-- Groupe inexistant → erreur, rien n'est créé
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('app_bad', 'regress_app_x', 'regress_app_y', 'regress_no_such_group')$$) <> 'ok' AS missing_group_refused;
SELECT count(*) AS pair_rows FROM pass_policy.rotation_pair WHERE pair_name = 'app_bad';

-- regress_app_a existe déjà (créé à la main), regress_app_b sera créé
CREATE ROLE regress_app_a LOGIN;
SELECT pass_policy.create_rotation_pair('app', 'regress_app_a', 'regress_app_b', 'regress_app_grp');
SELECT pair_name, role_a, role_b, group_role
  FROM pass_policy.rotation_pair WHERE pair_name = 'app';

-- Les deux rôles existent, LOGIN, membres du groupe avec INHERIT
SELECT r.rolname, r.rolcanlogin, r.rolinherit,
       pg_has_role(r.rolname, 'regress_app_grp', 'MEMBER') AS member,
       pg_has_role(r.rolname, 'regress_app_grp', 'USAGE') AS inherits
  FROM pg_roles r WHERE r.rolname IN ('regress_app_a', 'regress_app_b')
 ORDER BY 1;

-- Paire en double refusée
SELECT ppp_test.try($$SELECT pass_policy.create_rotation_pair('app', 'regress_app_a', 'regress_app_b', 'regress_app_grp')$$) <> 'ok' AS duplicate_refused;

-- Premier basculement
CREATE TABLE ppp_test.switches (n int, active_role text, password text,
                                previous_role text, previous_valid_until timestamptz);
INSERT INTO ppp_test.switches
  SELECT 1, * FROM pass_policy.switch_rotation_pair('app');
INSERT INTO ppp_test.secrets SELECT 'pair1', password FROM ppp_test.switches WHERE n = 1;
SELECT active_role IN ('regress_app_a', 'regress_app_b') AS active_ok,
       length(password) AS len
  FROM ppp_test.switches WHERE n = 1;
SELECT p.active_role = s.active_role AS pair_active_ok
  FROM pass_policy.rotation_pair p, ppp_test.switches s
 WHERE p.pair_name = 'app' AND s.n = 1;
-- Le mot de passe renvoyé est celui du rôle actif (présent dans son historique)
SELECT ppp_test.code(pass_policy.check_password(active_role, password)) AS reuse
  FROM ppp_test.switches WHERE n = 1;

-- Second basculement : l'autre rôle devient actif, l'ancien a un VALID UNTIL borné
INSERT INTO ppp_test.switches
  SELECT 2, * FROM pass_policy.switch_rotation_pair('app', 32);
INSERT INTO ppp_test.secrets SELECT 'pair2', password FROM ppp_test.switches WHERE n = 2;
SELECT s2.active_role <> s1.active_role AS alternated,
       s2.previous_role = s1.active_role AS previous_ok,
       length(s2.password) AS len,
       s2.password <> s1.password AS new_password
  FROM ppp_test.switches s1, ppp_test.switches s2
 WHERE s1.n = 1 AND s2.n = 2;
-- previous_valid_until = now() + grace_period du profil (default : 7 jours)
SELECT previous_valid_until > now() AS in_future,
       previous_valid_until <= now() + interval '7 days 01:00' AS bounded_by_grace
  FROM ppp_test.switches WHERE n = 2;
SELECT abs(extract(epoch FROM r.rolvaliduntil - s.previous_valid_until)) < 2 AS valid_until_applied
  FROM ppp_test.switches s JOIN pg_roles r ON r.rolname = s.previous_role
 WHERE s.n = 2;
SELECT p.previous_role = s.previous_role AS pair_previous_ok,
       abs(extract(epoch FROM p.previous_valid_until - s.previous_valid_until)) < 2 AS pair_valid_until_ok,
       p.switched_at > now() - interval '1 minute' AS switched_recently
  FROM pass_policy.rotation_pair p, ppp_test.switches s
 WHERE p.pair_name = 'app' AND s.n = 2;

-- Troisième basculement : retour au premier rôle actif
INSERT INTO ppp_test.switches
  SELECT 3, * FROM pass_policy.switch_rotation_pair('app');
INSERT INTO ppp_test.secrets SELECT 'pair3', password FROM ppp_test.switches WHERE n = 3;
SELECT s3.active_role = s1.active_role AS back_to_first
  FROM ppp_test.switches s1, ppp_test.switches s3 WHERE s1.n = 1 AND s3.n = 3;

-- Les deux rôles restent membres du groupe
SELECT count(*) AS members
  FROM pg_auth_members m
 WHERE m.roleid = 'regress_app_grp'::regrole
   AND m.member IN ('regress_app_a'::regrole, 'regress_app_b'::regrole);

-- Audit pair_switched sans mot de passe
SELECT count(*) AS switch_events FROM pass_policy.audit_log
 WHERE event_type = 'pair_switched';
SELECT ppp_test.leaks();

-- Paire inconnue
SELECT ppp_test.try($$SELECT * FROM pass_policy.switch_rotation_pair('no_such_pair')$$) <> 'ok' AS unknown_pair_refused;

DROP TABLE ppp_test.switches;
