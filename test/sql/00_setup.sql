--
-- 00_setup — installation de l'extension et vérification des objets (SPEC §3, §4, §5)
--
-- Conventions communes à tous les tests :
--   * les rôles de test sont préfixés regress_ (convention pg_regress) ;
--   * les mots de passe de test n'apparaissent que dans le texte des commandes,
--     jamais dans un résultat : on n'affiche que des booléens, des longueurs ou
--     des codes PPP-xxx ;
--   * aucun horodatage n'est affiché (PGTZ/datestyle de pg_regress) ;
--   * le worker est désactivé (worker_interval = 0 dans test/pg_pass_policy.conf)
--     pour que run_maintenance() appelé par les tests soit déterministe.
--
\set VERBOSITY terse
SET client_min_messages = warning;

-- Rôle « antérieur à l'extension » : son mot de passe est posé avant
-- CREATE EXTENSION. Il sert à la réconciliation dans 70_maintenance.
-- Le hook peut émettre un WARNING (schéma absent) : on le masque.
SET client_min_messages = error;
CREATE ROLE regress_legacy LOGIN PASSWORD 'Legacy-Passw0rd#2019';
SET client_min_messages = warning;

CREATE EXTENSION pg_pass_policy;

SELECT extname, extversion, extnamespace::regnamespace AS schema
  FROM pg_extension WHERE extname = 'pg_pass_policy';

-- Tables (SPEC §3)
SELECT c.relname, c.relkind
  FROM pg_class c
 WHERE c.relnamespace = 'pass_policy'::regnamespace
   AND c.relkind IN ('r', 'v')
 ORDER BY c.relkind, c.relname;

-- Colonnes de la table profile (SPEC §3.1)
SELECT attname, format_type(atttypid, atttypmod) AS type
  FROM pg_attribute
 WHERE attrelid = 'pass_policy.profile'::regclass
   AND attnum > 0 AND NOT attisdropped
 ORDER BY attnum;

-- Colonnes de role_state (SPEC §3.3)
SELECT attname, format_type(atttypid, atttypmod) AS type
  FROM pg_attribute
 WHERE attrelid = 'pass_policy.role_state'::regclass
   AND attnum > 0 AND NOT attisdropped
 ORDER BY attnum;

-- Aucun droit pour PUBLIC sur les tables
SELECT c.relname
  FROM pg_class c
 WHERE c.relnamespace = 'pass_policy'::regnamespace
   AND c.relkind = 'r'
   AND has_table_privilege('public', c.oid, 'SELECT')
 ORDER BY 1;

-- Fonctions (SPEC §4) : présence, langage et SECURITY DEFINER
SELECT p.proname, l.lanname, p.prosecdef
  FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
 WHERE p.pronamespace = 'pass_policy'::regnamespace
   AND p.proname IN ('create_profile', 'alter_profile', 'drop_profile',
                     'assign_profile', 'unassign_profile', 'effective_profile',
                     'check_password', 'generate_password', 'rotate_password',
                     'expire_password', 'lock_role', 'unlock_role',
                     'record_password_change', 'run_maintenance',
                     'create_rotation_pair', 'switch_rotation_pair',
                     'purge_audit', 'load_dictionary', 'audit',
                     'failed_attempts', 'shmem_reload', 'shmem_lock_role',
                     'shmem_unlock_role', 'shmem_reset_failures',
                     'worker_status')
 ORDER BY p.proname;

-- Les fonctions C attendues sont bien en C
SELECT p.proname
  FROM pg_proc p
 WHERE p.pronamespace = 'pass_policy'::regnamespace
   AND p.proname IN ('check_password', 'generate_password', 'failed_attempts',
                     'shmem_reload', 'shmem_lock_role', 'shmem_unlock_role',
                     'shmem_reset_failures', 'worker_status', '_is_exempt',
                     '_in_password_hook')
   AND p.prolang <> (SELECT oid FROM pg_language WHERE lanname = 'c')
 ORDER BY 1;

-- Rôles créés par l'extension
SELECT rolname, rolcanlogin, rolsuper
  FROM pg_roles
 WHERE rolname IN ('pass_policy_admin', 'pass_policy_viewer')
 ORDER BY 1;

-- Profil default présent avec les valeurs de SPEC §3.1
SELECT name, min_length, max_length, min_lower, min_upper, min_digit,
       min_special, min_classes, reject_username, reject_dictionary,
       reject_prehashed, max_repeat, history_count, history_days,
       max_age, min_age, grace_period, warn_before, max_failures,
       failure_window, lock_duration
  FROM pass_policy.profile WHERE name = 'default';

-- Dictionnaire préchargé (~200 mots, en minuscules)
SELECT count(*) >= 100 AS dictionary_loaded,
       bool_and(word = lower(word)) AS all_lowercase,
       bool_or(word = 'password') AS has_password
  FROM pass_policy.dictionary;

-- GUC (SPEC §5)
SHOW pg_pass_policy.enabled;
SHOW pg_pass_policy.database;
SHOW pg_pass_policy.worker_interval;
SHOW pg_pass_policy.max_tracked_roles;
SHOW pg_pass_policy.manage_valid_until;
SHOW pg_pass_policy.log_events;
SHOW pg_pass_policy.notify_channel;
SHOW pg_pass_policy.exempt_roles;
SHOW pg_pass_policy.superuser_bypass;
SHOW pg_pass_policy.require_scram;
SHOW pg_pass_policy.enforce_database;
SELECT name, context FROM pg_settings
 WHERE name LIKE 'pg\_pass\_policy.%' ORDER BY name;

-- Préfixe réservé : un GUC inconnu est refusé (PG >= 15) ou signalé (PG 14).
-- Non affiché : le comportement diffère selon la version.

-- Worker : une seule ligne, le pid peut être NULL selon le timing de démarrage
SELECT count(*) AS worker_rows FROM pass_policy.worker_status();

-- Outils de test (schéma ppp_test, supprimé dans 99_teardown)
CREATE SCHEMA ppp_test;
GRANT USAGE ON SCHEMA ppp_test TO PUBLIC;

-- Exécute une commande, renvoie 'ok' ou 'SQLSTATE [PPP-xxx]'.
-- Permet de rendre les sorties indépendantes du libellé exact des messages.
CREATE FUNCTION ppp_test.try(stmt text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
  RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE || coalesce(' ' || substring(SQLERRM FROM '^PPP-[0-9]{3}'), '');
END $$;
GRANT EXECUTE ON FUNCTION ppp_test.try(text) TO PUBLIC;

-- Code PPP-xxx seul d'un motif de refus renvoyé par check_password()
CREATE FUNCTION ppp_test.code(reason text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT substring(reason FROM '^PPP-[0-9]{3}') $$;

-- Secrets connus des tests (mots de passe posés ou générés), utilisés pour
-- vérifier qu'ils n'apparaissent jamais dans l'audit ni dans l'historique.
CREATE TABLE ppp_test.secrets (label text PRIMARY KEY, pwd text NOT NULL);
GRANT ALL ON ppp_test.secrets TO PUBLIC;
INSERT INTO ppp_test.secrets VALUES ('legacy', 'Legacy-Passw0rd#2019');

-- Fuites : lignes d'audit ou d'historique contenant un secret connu, ou
-- d'audit contenant un vérificateur. Les secrets de moins de 10 caractères
-- sont ignorés (faux positifs possibles dans les vérificateurs base64).
CREATE FUNCTION ppp_test.leaks() RETURNS bigint
LANGUAGE sql AS $$
  SELECT (SELECT count(*) FROM pass_policy.audit_log a, ppp_test.secrets s
           WHERE length(s.pwd) >= 10
             AND strpos(coalesce(a.details::text, '') || coalesce(a.role_name, ''), s.pwd) > 0)
       + (SELECT count(*) FROM pass_policy.password_history h, ppp_test.secrets s
           WHERE length(s.pwd) >= 10 AND strpos(h.verifier, s.pwd) > 0)
       + (SELECT count(*) FROM pass_policy.audit_log a
           WHERE a.details::text LIKE '%SCRAM-SHA-256$%'
              OR a.details::text ~ 'md5[0-9a-f]{32}')
$$;

SELECT ppp_test.leaks();

-- Rôle antérieur à l'extension : date de changement inconnue, pas d'historique
-- (avant tout run_maintenance ; la réconciliation est testée dans 70_maintenance)
SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_legacy';
SELECT count(*) AS history_rows FROM pass_policy.password_history
 WHERE role_name = 'regress_legacy';
