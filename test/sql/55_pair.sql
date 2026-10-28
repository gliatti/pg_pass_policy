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

-- L'ancien rôle est borné dans role_state (statut grace jusqu'à la borne), pas
-- seulement par dérivation de rotation_pair : si la ligne de la paire disparaît,
-- la synchronisation suivante ne doit pas réactiver l'ancien mot de passe.
SELECT v.status, s.must_change,
       abs(extract(epoch FROM s.grace_until - w.previous_valid_until)) < 2 AS state_bounded
  FROM ppp_test.switches w
  JOIN pass_policy.v_role_status v ON v.role_name = w.previous_role
  JOIN pass_policy.role_state s ON s.role_name = w.previous_role
 WHERE w.n = 3;
CREATE TEMP TABLE pair_backup AS SELECT * FROM pass_policy.rotation_pair WHERE pair_name = 'app';
DELETE FROM pass_policy.rotation_pair WHERE pair_name = 'app';
CREATE TEMP TABLE m_pair AS SELECT * FROM pass_policy.run_maintenance();
SELECT abs(extract(epoch FROM r.rolvaliduntil - w.previous_valid_until)) < 2 AS unchanged_after_delete,
       r.rolvaliduntil <= now() + interval '7 days 01:00' AS still_bounded
  FROM ppp_test.switches w JOIN pg_roles r ON r.rolname = w.previous_role
 WHERE w.n = 3;
INSERT INTO pass_policy.rotation_pair SELECT * FROM pair_backup;
-- Filet de run_maintenance (étape a) pour une paire basculée avant que
-- role_state porte la borne (simulé) : la purge de la paire, ici parce que le
-- groupe n'existe plus, reporte previous_valid_until dans role_state
UPDATE pass_policy.role_state
   SET must_change = false, expires_at = now() + interval '30 days', grace_until = now() + interval '37 days'
 WHERE role_name = (SELECT previous_role FROM ppp_test.switches WHERE n = 3);
ALTER ROLE regress_app_grp RENAME TO regress_app_grp_gone;
CREATE TEMP TABLE m_pair2 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS pair_purged FROM m_pair2 WHERE action = 'purge' AND details->>'table' = 'rotation_pair';
SELECT s.must_change,
       abs(extract(epoch FROM s.grace_until - w.previous_valid_until)) < 2 AS state_bounded,
       abs(extract(epoch FROM r.rolvaliduntil - w.previous_valid_until)) < 2 AS valid_until_unchanged
  FROM ppp_test.switches w
  JOIN pass_policy.role_state s ON s.role_name = w.previous_role
  JOIN pg_roles r ON r.rolname = w.previous_role
 WHERE w.n = 3;
ALTER ROLE regress_app_grp_gone RENAME TO regress_app_grp;
INSERT INTO pass_policy.rotation_pair SELECT * FROM pair_backup;

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

-- (vérification 6) manage_valid_until = off : _rotate_role() ne relève
-- qu'une borne passée (mode unblock). Après deux basculements rapides, le
-- rôle qui redevient actif garde la borne future posée par le premier
-- (previous_valid_until) : elle est levée (mode release), sinon le rôle actif
-- serait bloqué à la fin de grace_period. L'ancien rôle reste borné.
ALTER SYSTEM SET pg_pass_policy.manage_valid_until = off;
SELECT pg_reload_conf();
\set ECHO none
\o /dev/null
SELECT 'SELECT pg_sleep(0.1) WHERE current_setting(''pg_pass_policy.manage_valid_until'')::bool'
  FROM generate_series(1, 50) \gexec
\o
\set ECHO all
SHOW pg_pass_policy.manage_valid_until;
CREATE ROLE regress_off2_grp NOLOGIN;
SELECT pass_policy.create_rotation_pair('off2', 'regress_off2_a', 'regress_off2_b', 'regress_off2_grp');
CREATE TEMP TABLE off2 (n int, active_role text, password text,
                        previous_role text, previous_valid_until timestamptz);
INSERT INTO off2 SELECT 1, * FROM pass_policy.switch_rotation_pair('off2');
INSERT INTO off2 SELECT 2, * FROM pass_policy.switch_rotation_pair('off2');
INSERT INTO off2 SELECT 3, * FROM pass_policy.switch_rotation_pair('off2');
INSERT INTO ppp_test.secrets SELECT 'off2_' || n, password FROM off2;
SELECT o3.active_role = o1.active_role AS back_to_first,
       r.rolvaliduntil IS NULL OR r.rolvaliduntil = 'infinity' AS active_unbounded
  FROM off2 o1, off2 o3 JOIN pg_roles r ON r.rolname = o3.active_role
 WHERE o1.n = 1 AND o3.n = 3;
SELECT abs(extract(epoch FROM r.rolvaliduntil - o.previous_valid_until)) < 2 AS previous_bounded
  FROM off2 o JOIN pg_roles r ON r.rolname = o.previous_role
 WHERE o.n = 3;
SELECT ppp_test.leaks();
DROP TABLE off2;
ALTER SYSTEM RESET pg_pass_policy.manage_valid_until;
SELECT pg_reload_conf();
\set ECHO none
\o /dev/null
SELECT 'SELECT pg_sleep(0.1) WHERE NOT current_setting(''pg_pass_policy.manage_valid_until'')::bool'
  FROM generate_series(1, 50) \gexec
\o
\set ECHO all
SHOW pg_pass_policy.manage_valid_until;
