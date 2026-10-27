--
-- 70_maintenance — run_maintenance() : expiration, alertes, VALID UNTIL, purge,
-- réconciliation (SPEC §3.3, §4 run_maintenance, §6.4)
--
-- Le worker est désactivé dans la configuration de test (worker_interval = 0) :
-- seules les invocations explicites de run_maintenance() agissent.
-- Le résultat de run_maintenance() n'est jamais affiché tel quel (il dépend de
-- l'état laissé par les tests précédents) : on filtre sur les rôles du test.
--
\set VERBOSITY terse
SET client_min_messages = warning;

-- Statuts de v_role_status selon le profil
SELECT pass_policy.create_profile('p_short',
         '{"max_age": "1 second", "grace_period": "1 second",
           "warn_before": "1 second", "min_age": "0"}') > 0 AS created;
SELECT pass_policy.create_profile('p_grace',
         '{"max_age": "1 second", "grace_period": "1 hour",
           "warn_before": "1 second", "min_age": "0"}') > 0 AS created;
SELECT pass_policy.create_profile('p_warn',
         '{"max_age": "1 day", "warn_before": "2 days", "min_age": "0"}') > 0 AS created;
SELECT pass_policy.create_profile('p_never', '{"max_age": null, "min_age": "0"}') > 0 AS created;

CREATE ROLE regress_maint LOGIN;
CREATE ROLE regress_maint_grace LOGIN;
CREATE ROLE regress_maint_warn LOGIN;
CREATE ROLE regress_maint_never LOGIN;
SELECT pass_policy.assign_profile('regress_maint', 'p_short');
SELECT pass_policy.assign_profile('regress_maint_grace', 'p_grace');
SELECT pass_policy.assign_profile('regress_maint_warn', 'p_warn');
SELECT pass_policy.assign_profile('regress_maint_never', 'p_never');

INSERT INTO ppp_test.secrets VALUES
  ('maint1', 'Maintenance-Pw#01'), ('maint2', 'Maintenance-Pw#02'),
  ('maint3', 'Maintenance-Pw#03'), ('maint4', 'Maintenance-Pw#04');
ALTER ROLE regress_maint PASSWORD 'Maintenance-Pw#01';
-- Tout de suite : expires_at − now() < warn_before → alerte
CREATE TEMP TABLE m1 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) > 0 AS warned
  FROM pass_policy.audit_log
 WHERE event_type = 'expiry_warning' AND role_name = 'regress_maint';
SELECT last_warned_at IS NOT NULL AS last_warned_set
  FROM pass_policy.role_state WHERE role_name = 'regress_maint';

ALTER ROLE regress_maint_grace PASSWORD 'Maintenance-Pw#02';
ALTER ROLE regress_maint_warn PASSWORD 'Maintenance-Pw#03';
ALTER ROLE regress_maint_never PASSWORD 'Maintenance-Pw#04';

-- expires_at / grace_until calculés au changement
SELECT role_name,
       expires_at - password_changed_at AS lifetime,
       grace_until - expires_at AS grace
  FROM pass_policy.role_state
 WHERE role_name IN ('regress_maint', 'regress_maint_grace')
 ORDER BY role_name;
SELECT expires_at IS NULL AS no_expiry, grace_until IS NULL AS no_grace
  FROM pass_policy.role_state WHERE role_name = 'regress_maint_never';

SELECT pg_sleep(2.5);
CREATE TEMP TABLE m2 AS SELECT * FROM pass_policy.run_maintenance();

SELECT role_name, status
  FROM pass_policy.v_role_status
 WHERE role_name IN ('regress_maint', 'regress_maint_grace',
                     'regress_maint_warn', 'regress_maint_never')
 ORDER BY role_name;
SELECT role_name, status FROM pass_policy.v_expiring
 WHERE role_name LIKE 'regress\_maint%' ORDER BY role_name;
SELECT days_left IS NULL AS never_days_left_null
  FROM pass_policy.v_role_status WHERE role_name = 'regress_maint_never';

-- VALID UNTIL synchronisé = grace_until (manage_valid_until = on)
SELECT r.rolname,
       abs(extract(epoch FROM r.rolvaliduntil - s.grace_until)) < 2 AS synced,
       abs(extract(epoch FROM s.valid_until_synced - s.grace_until)) < 2 AS recorded
  FROM pg_roles r JOIN pass_policy.role_state s ON s.role_name = r.rolname
 WHERE r.rolname IN ('regress_maint', 'regress_maint_grace', 'regress_maint_warn')
 ORDER BY 1;
SELECT rolvaliduntil < now() AS past FROM pg_roles WHERE rolname = 'regress_maint';

-- Audit : password_expired pour regress_maint (une seule fois même après 2 passes)
CREATE TEMP TABLE m3 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS expired_events FROM pass_policy.audit_log
 WHERE event_type = 'password_expired' AND role_name = 'regress_maint';
SELECT count(*) AS expired_events_grace FROM pass_policy.audit_log
 WHERE event_type = 'password_expired' AND role_name = 'regress_maint_grace';
-- La valeur de retour décrit les actions (colonnes action, role_name, details)
SELECT count(*) > 0 AS reported
  FROM (SELECT * FROM m1 UNION ALL SELECT * FROM m2) m
 WHERE m.role_name LIKE 'regress\_maint%';
-- Les actions retournées ne contiennent ni mot de passe ni vérificateur
SELECT count(*) AS leaking_actions
  FROM (SELECT * FROM m1 UNION ALL SELECT * FROM m2 UNION ALL SELECT * FROM m3) m
 WHERE m.details::text LIKE '%SCRAM-SHA-256$%'
    OR EXISTS (SELECT 1 FROM ppp_test.secrets s
                WHERE length(s.pwd) >= 10 AND strpos(m.details::text, s.pwd) > 0);

-- Changement de profil : la synchronisation suit le nouveau max_age
SELECT pass_policy.alter_profile('p_short', '{"max_age": "10 days", "grace_period": "1 day"}');
CREATE TEMP TABLE m4 AS SELECT * FROM pass_policy.run_maintenance();
SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_maint';
SELECT rolvaliduntil > now() + interval '10 days' AS resynced
  FROM pg_roles WHERE rolname = 'regress_maint';

-- Rôle supprimé : purge de role_state, role_profile et password_history
CREATE ROLE regress_gone LOGIN;
SELECT pass_policy.assign_profile('regress_gone', 'p_never');
ALTER ROLE regress_gone PASSWORD 'Gone-Soon#2024xy';
INSERT INTO ppp_test.secrets VALUES ('gone', 'Gone-Soon#2024xy');
DROP ROLE regress_gone;
CREATE TEMP TABLE m5 AS SELECT * FROM pass_policy.run_maintenance();
SELECT (SELECT count(*) FROM pass_policy.role_state WHERE role_name = 'regress_gone') AS state_rows,
       (SELECT count(*) FROM pass_policy.role_profile WHERE role_name = 'regress_gone') AS profile_rows,
       (SELECT count(*) FROM pass_policy.password_history WHERE role_name = 'regress_gone') AS history_rows;

-- Renommage puis recréation de l'ancien nom : les lignes suivent l'OID. Le
-- rôle renommé garde verrou, profil et historique ; le nouveau rôle qui porte
-- l'ancien nom n'hérite de rien (seules les lignes dont l'OID a disparu sont
-- rattachées par nom).
CREATE ROLE regress_alice LOGIN;
ALTER ROLE regress_alice PASSWORD 'Alice-Rename#2024';
INSERT INTO ppp_test.secrets VALUES ('alice', 'Alice-Rename#2024');
SELECT pass_policy.assign_profile('regress_alice', 'p_never');
SELECT pass_policy.lock_role('regress_alice', NULL, 'rename test') = 'infinity' AS locked;
ALTER ROLE regress_alice RENAME TO regress_bob;
CREATE ROLE regress_alice LOGIN;
-- Avant run_maintenance() : role_state.role_name porte encore l'ancien nom,
-- v_locked joint role_state par OID (role_oid exposé par v_role_status) et
-- affiche l'origine et le motif du verrou sous le nouveau nom
SELECT s.role_name AS stale_name FROM pass_policy.role_state s
 WHERE s.role_oid = 'regress_bob'::regrole::oid;
-- (regress_alice n'est pas affiché : la mémoire partagée, indexée par nom,
-- peut garder le verrou sous l'ancien nom jusqu'au rechargement du worker)
SELECT role_name, locked_by, lock_reason FROM pass_policy.v_locked
 WHERE role_name = 'regress_bob';
SELECT role_oid = 'regress_bob'::regrole::oid AS status_oid_ok
  FROM pass_policy.v_role_status WHERE role_name = 'regress_bob';
CREATE TEMP TABLE m_rename AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS remapped FROM m_rename WHERE action = 'remap';
SELECT s.role_name, s.locked_until = 'infinity' AS locked, s.role_oid = 'regress_bob'::regrole::oid AS oid_ok
  FROM pass_policy.role_state s WHERE s.role_name IN ('regress_alice', 'regress_bob')
 ORDER BY 1;
SELECT p.role_name, p.role_oid = 'regress_bob'::regrole::oid AS oid_ok
  FROM pass_policy.role_profile p WHERE p.role_name IN ('regress_alice', 'regress_bob')
 ORDER BY 1;
SELECT h.role_name, count(*) AS history_rows,
       bool_and(h.role_oid = 'regress_bob'::regrole::oid) AS oid_ok
  FROM pass_policy.password_history h WHERE h.role_name IN ('regress_alice', 'regress_bob')
 GROUP BY 1 ORDER BY 1;
SELECT pass_policy.unlock_role('regress_bob');
SELECT pass_policy.unassign_profile('regress_bob');

-- lock_role(), unlock_role() et expire_password() rafraîchissent
-- role_state.role_name (nom courant) sans attendre run_maintenance()
CREATE ROLE regress_ren1 LOGIN;
SELECT pass_policy.lock_role('regress_ren1', interval '1 hour') IS NOT NULL AS locked;
ALTER ROLE regress_ren1 RENAME TO regress_ren2;
SELECT pass_policy.unlock_role('regress_ren2');
SELECT role_name AS after_unlock FROM pass_policy.role_state WHERE role_oid = 'regress_ren2'::regrole::oid;
ALTER ROLE regress_ren2 RENAME TO regress_ren3;
SELECT pass_policy.lock_role('regress_ren3', interval '1 hour') IS NOT NULL AS locked;
SELECT role_name AS after_lock FROM pass_policy.role_state WHERE role_oid = 'regress_ren3'::regrole::oid;
ALTER ROLE regress_ren3 RENAME TO regress_ren4;
SELECT pass_policy.expire_password('regress_ren4');
SELECT role_name AS after_expire FROM pass_policy.role_state WHERE role_oid = 'regress_ren4'::regrole::oid;
SELECT pass_policy.unlock_role('regress_ren4');

-- Déverrouillage automatique (étape f) d'un rôle renommé : le verrou en
-- mémoire partagée (indexée par nom) et l'audit portent le nom courant.
CREATE ROLE regress_carol LOGIN;
SELECT pass_policy.lock_role('regress_carol', interval '3 seconds', 'rename auto unlock')
       = now() + interval '3 seconds' AS lock_returned;
ALTER ROLE regress_carol RENAME TO regress_dave;
-- le worker (réveillé par shmem_reload()) réinjecte le verrou sous le nouveau
-- nom ; attente bornée à 5 s, une instruction par tour
SELECT pass_policy.shmem_reload();
\set ECHO none
\o /dev/null
SELECT 'SELECT pg_sleep(0.1) WHERE NOT EXISTS (SELECT FROM pass_policy.failed_attempts() '
       'WHERE role_name = ''regress_dave'' AND locked_until > now())'
  FROM generate_series(1, 50) \gexec
\o
\set ECHO all
SELECT count(*) AS dave_locked_in_shmem FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_dave' AND locked_until > now();
SELECT pg_sleep(3.5);
CREATE TEMP TABLE m_unlock AS SELECT * FROM pass_policy.run_maintenance();
SELECT action, role_name FROM m_unlock
 WHERE action = 'role_unlocked' AND role_name IN ('regress_carol', 'regress_dave');
SELECT role_name, details->>'by' AS by FROM pass_policy.audit_log
 WHERE event_type = 'role_unlocked' AND role_name IN ('regress_carol', 'regress_dave');
SELECT count(*) AS dave_lock_left FROM pass_policy.failed_attempts()
 WHERE role_name = 'regress_dave' AND locked_until IS NOT NULL;
SELECT role_name, locked_until IS NULL AS unlocked FROM pass_policy.role_state
 WHERE role_oid = 'regress_dave'::regrole::oid;

-- Réconciliation 1 : rôle dont le mot de passe a été posé avant CREATE EXTENSION
-- (regress_legacy, créé dans 00_setup, statut unknown vérifié dans 00_setup).
-- Des run_maintenance() ont eu lieu depuis (20, 60, ici) : l'historique
-- contient son vérificateur.
CREATE TEMP TABLE m6 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS history_after,
       bool_and(verifier LIKE 'SCRAM-SHA-256$%') AS scram
  FROM pass_policy.password_history WHERE role_name = 'regress_legacy';
-- Le mot de passe historique est désormais détecté comme réutilisation
SELECT ppp_test.code(pass_policy.check_password('regress_legacy', 'Legacy-Passw0rd#2019')) AS reuse;
-- Une seconde passe ne duplique pas l'historique
CREATE TEMP TABLE m7 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS history_after_2nd_run FROM pass_policy.password_history
 WHERE role_name = 'regress_legacy';

-- Réconciliation 2 : mot de passe changé pendant que pg_pass_policy.enabled = off.
-- enabled est de contexte SIGHUP : SET est impossible, on passe par ALTER SYSTEM.
SELECT ppp_test.try($$SET pg_pass_policy.enabled = off$$) <> 'ok' AS set_refused;
CREATE ROLE regress_recon LOGIN;
ALTER SYSTEM SET pg_pass_policy.enabled = off;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SHOW pg_pass_policy.enabled;
-- Mot de passe faible accepté : la politique est désactivée, rien n'est enregistré
ALTER ROLE regress_recon PASSWORD 'recon-weak-password';
ALTER ROLE regress_recon PASSWORD 'Recon-Disabled#01';
INSERT INTO ppp_test.secrets VALUES ('recon_weak', 'recon-weak-password'),
                                    ('recon', 'Recon-Disabled#01');
ALTER SYSTEM RESET pg_pass_policy.enabled;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SHOW pg_pass_policy.enabled;
SELECT count(*) AS history_before FROM pass_policy.password_history
 WHERE role_name = 'regress_recon';
CREATE TEMP TABLE m8 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS history_after FROM pass_policy.password_history
 WHERE role_name = 'regress_recon';
SELECT ppp_test.code(pass_policy.check_password('regress_recon', 'Recon-Disabled#01')) AS reuse;

-- manage_valid_until = off : le worker ne gère plus VALID UNTIL, mais une
-- borne qu'il a posée lui-même (expire_password) est levée une fois le mot de
-- passe changé (mode unblock), sinon le rôle resterait bloqué indéfiniment.
ALTER SYSTEM SET pg_pass_policy.manage_valid_until = off;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SHOW pg_pass_policy.manage_valid_until;
CREATE ROLE regress_unblock LOGIN;
ALTER ROLE regress_unblock PASSWORD 'Unblock-Pw#2024x';
INSERT INTO ppp_test.secrets VALUES ('unblock1', 'Unblock-Pw#2024x'), ('unblock2', 'Unblock-Pw#2024y');
SELECT pass_policy.expire_password('regress_unblock');
SELECT rolvaliduntil <= now() AS blocked FROM pg_roles WHERE rolname = 'regress_unblock';
-- tant que le mot de passe n'est pas changé, rien n'est relevé
CREATE TEMP TABLE m9 AS SELECT * FROM pass_policy.run_maintenance();
SELECT count(*) AS synced_before_change FROM m9
 WHERE role_name = 'regress_unblock' AND action = 'valid_until_synced';
SELECT rolvaliduntil <= now() AS still_blocked FROM pg_roles WHERE rolname = 'regress_unblock';
ALTER ROLE regress_unblock PASSWORD 'Unblock-Pw#2024y';
SELECT action, role_name, details->>'mode' AS mode
  FROM pass_policy.run_maintenance() WHERE role_name = 'regress_unblock';
SELECT rolvaliduntil > now() AS unblocked FROM pg_roles WHERE rolname = 'regress_unblock';
-- … à « infinity », et non à grace_until : personne ne relèverait plus
-- cette nouvelle borne une fois passée (manage_valid_until = off)
SELECT rolvaliduntil = 'infinity' AS unblocked_infinity FROM pg_roles WHERE rolname = 'regress_unblock';
-- rotate_password() et switch_rotation_pair() suivent la même règle : pas de
-- VALID UNTIL posé quand manage_valid_until = off
CREATE ROLE regress_off_rot LOGIN;
INSERT INTO ppp_test.secrets SELECT 'off_rot', pass_policy.rotate_password('regress_off_rot');
SELECT rolvaliduntil IS NULL AS rotate_no_valid_until FROM pg_roles WHERE rolname = 'regress_off_rot';
CREATE ROLE regress_off_grp NOLOGIN;
SELECT pass_policy.create_rotation_pair('off_pair', 'regress_off_a', 'regress_off_b', 'regress_off_grp');
CREATE TEMP TABLE off_switch AS SELECT * FROM pass_policy.switch_rotation_pair('off_pair');
INSERT INTO ppp_test.secrets SELECT 'off_pair', password FROM off_switch;
SELECT r.rolvaliduntil IS NULL AS switch_no_valid_until
  FROM off_switch o JOIN pg_roles r ON r.rolname = o.active_role;
DROP TABLE off_switch;
ALTER SYSTEM RESET pg_pass_policy.manage_valid_until;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SHOW pg_pass_policy.manage_valid_until;

-- Restauration dans un autre cluster : les OID changent et l'ancien OID d'un
-- rôle peut appartenir à un autre. Simulation par UPDATE direct : les lignes
-- de regress_rx et de regress_ry échangent leurs OID (passage par l'OID 1,
-- qui n'est pas un rôle), plus des lignes d'un rôle absent du cluster.
-- rebind_restored_roles() les rattache par nom, en une passe, quel que soit
-- l'ordre ; le test S3 ci-dessus (renommage) n'est pas concerné : il ne
-- passe que par run_maintenance().
CREATE ROLE regress_rx LOGIN;
CREATE ROLE regress_ry LOGIN;
ALTER ROLE regress_rx PASSWORD 'Rebind-Rx#2024ab';
ALTER ROLE regress_ry PASSWORD 'Rebind-Ry#2024ab';
INSERT INTO ppp_test.secrets VALUES ('rx', 'Rebind-Rx#2024ab'), ('ry', 'Rebind-Ry#2024ab');
SELECT pass_policy.assign_profile('regress_rx', 'p_never');
SELECT pass_policy.assign_profile('regress_ry', 'p_short');
SELECT pass_policy.lock_role('regress_rx', NULL, 'rebind test') = 'infinity' AS locked;
CREATE TEMP TABLE rb_oids AS
SELECT 'regress_rx'::regrole::oid AS x, 'regress_ry'::regrole::oid AS y;
DO $$
DECLARE
    t text;
    x oid := (SELECT x FROM rb_oids);
    y oid := (SELECT y FROM rb_oids);
BEGIN
    FOREACH t IN ARRAY ARRAY['role_state', 'role_profile', 'password_history']
    LOOP
        EXECUTE format('UPDATE pass_policy.%I SET role_oid = 1 WHERE role_oid = $1', t) USING x;
        EXECUTE format('UPDATE pass_policy.%I SET role_oid = $1 WHERE role_oid = $2', t) USING x, y;
        EXECUTE format('UPDATE pass_policy.%I SET role_oid = $1 WHERE role_oid = 1', t) USING y;
    END LOOP;
END $$;
INSERT INTO pass_policy.role_state (role_oid, role_name) VALUES (4000000001, 'regress_absent');
INSERT INTO pass_policy.password_history (role_oid, role_name, verifier)
SELECT y, 'regress_absent', 'SCRAM-SHA-256$4096:dummy' FROM rb_oids;
-- les couples (role_oid, role_name) ne correspondent plus à pg_authid
SELECT s.role_name, s.role_oid = (SELECT y FROM rb_oids) AS has_ry_oid
  FROM pass_policy.role_state s WHERE s.role_name = 'regress_rx';
CREATE TEMP TABLE rb AS SELECT * FROM pass_policy.rebind_restored_roles();
SELECT action, role_name, details->>'table' AS tbl, details->>'reason' AS reason,
       details->>'rows' AS nrows
  FROM rb WHERE role_name IN ('regress_rx', 'regress_ry', 'regress_absent')
 ORDER BY 2, 3, 1;
SELECT s.role_name, s.role_oid = s.role_name::regrole::oid AS oid_ok,
       s.locked_until = 'infinity' AS locked, s.lock_reason
  FROM pass_policy.role_state s WHERE s.role_name IN ('regress_rx', 'regress_ry')
 ORDER BY 1;
SELECT p.role_name, p.role_oid = p.role_name::regrole::oid AS oid_ok, f.name AS profile
  FROM pass_policy.role_profile p JOIN pass_policy.profile f USING (profile_id)
 WHERE p.role_name IN ('regress_rx', 'regress_ry') ORDER BY 1;
SELECT h.role_name, count(*) AS history_rows,
       bool_and(h.role_oid = h.role_name::regrole::oid) AS oid_ok
  FROM pass_policy.password_history h WHERE h.role_name IN ('regress_rx', 'regress_ry')
 GROUP BY 1 ORDER BY 1;
SELECT (SELECT count(*) FROM pass_policy.role_state WHERE role_name = 'regress_absent') AS absent_state,
       (SELECT count(*) FROM pass_policy.password_history WHERE role_name = 'regress_absent') AS absent_history;
SELECT event_type, details ? 'rebind_restored_roles' AS rebind_audit
  FROM pass_policy.audit_log ORDER BY id DESC LIMIT 1;
-- une seconde passe ne trouve plus rien
SELECT count(*) AS second_rebind FROM pass_policy.rebind_restored_roles();
-- run_maintenance() ne défait rien
CREATE TEMP TABLE rb_m AS SELECT * FROM pass_policy.run_maintenance();
SELECT s.role_name, s.role_oid = s.role_name::regrole::oid AS oid_ok
  FROM pass_policy.role_state s WHERE s.role_name IN ('regress_rx', 'regress_ry')
 ORDER BY 1;
SELECT pass_policy.unlock_role('regress_rx');
SELECT pass_policy.unassign_profile(r) FROM unnest(ARRAY['regress_rx', 'regress_ry']) r;
DROP TABLE rb_oids;

-- Étape a : une ligne d'historique encore sans OID dont le rôle existe n'est
-- pas purgée (elle est rattachée par a0, ou à la passe suivante si le rôle
-- n'est devenu visible qu'après a0) ; sans rôle de ce nom, elle l'est.
INSERT INTO pass_policy.password_history (role_oid, role_name, verifier)
VALUES (NULL, 'regress_rx', 'SCRAM-SHA-256$4096:dummy-null'),
       (NULL, 'regress_nobody', 'SCRAM-SHA-256$4096:dummy-null');
CREATE TEMP TABLE m_null AS SELECT * FROM pass_policy.run_maintenance();
SELECT role_name, role_oid = 'regress_rx'::regrole::oid AS mapped
  FROM pass_policy.password_history
 WHERE verifier = 'SCRAM-SHA-256$4096:dummy-null' ORDER BY 1;
DELETE FROM pass_policy.password_history WHERE verifier = 'SCRAM-SHA-256$4096:dummy-null';

-- Exclusion mutuelle : run_maintenance() prend un verrou consultatif de
-- transaction (pg_advisory_xact_lock) ; deux passes successives dans la même
-- transaction (verrou réentrant) réussissent, le verrou est tenu jusqu'au
-- COMMIT puis relâché
BEGIN;
SELECT count(*) >= 0 AS first_pass FROM pass_policy.run_maintenance();
SELECT count(*) >= 0 AS second_pass FROM pass_policy.run_maintenance();
SELECT count(*) AS advisory_held FROM pg_locks
 WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted;
COMMIT;
SELECT count(*) AS advisory_released FROM pg_locks
 WHERE locktype = 'advisory' AND pid = pg_backend_pid();
SELECT count(*) >= 0 AS third_pass FROM pass_policy.run_maintenance();

SELECT ppp_test.leaks();

-- Nettoyage des profils (les rôles sont supprimés dans 99_teardown)
SELECT pass_policy.unassign_profile(r)
  FROM unnest(ARRAY['regress_maint', 'regress_maint_grace',
                    'regress_maint_warn', 'regress_maint_never']) r;
SELECT pass_policy.drop_profile(p)
  FROM unnest(ARRAY['p_short', 'p_grace', 'p_warn', 'p_never']) p;
