\echo Use "CREATE EXTENSION pg_pass_policy" to load this file. \quit

/*
 * pg_pass_policy 1.0 — tables, SQL/PL/pgSQL API, views and declarations of
 * the C functions. Contract: docs/SPEC.md §3-§5 and §8.
 *
 * The schema "pass_policy" is created by CREATE EXTENSION (control file:
 * schema = pass_policy, relocatable = false, superuser = true), so every
 * object below is owned by the superuser that ran CREATE EXTENSION.  All
 * SECURITY DEFINER functions therefore run as superuser and pin
 * search_path = pg_catalog, pass_policy, pg_temp (pg_catalog first so a
 * built-in can never be shadowed; the extension schema is writable by
 * superusers only).
 *
 * Security rules (SPEC §8):
 *  - no clear-text password is ever stored, logged, raised or notified ;
 *  - dynamic SQL only through format('%I' / '%L') ;
 *  - administration functions check that session_user is a superuser or a
 *    member of pass_policy_admin (_require_admin()).
 */

-------------------------------------------------------------------------------
-- 1. Roles
-------------------------------------------------------------------------------
/*
 * Roles are cluster-wide objects and cannot be members of an extension: they
 * are created here only if missing and are NOT removed by DROP EXTENSION
 * (drop them by hand: DROP ROLE pass_policy_admin, pass_policy_viewer).
 * Re-creating the extension reuses them.
 */
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pass_policy_viewer') THEN
        CREATE ROLE pass_policy_viewer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pass_policy_admin') THEN
        CREATE ROLE pass_policy_admin NOLOGIN;
    END IF;
    IF NOT pg_catalog.pg_has_role('pass_policy_admin', 'pass_policy_viewer', 'MEMBER') THEN
        GRANT pass_policy_viewer TO pass_policy_admin;
    END IF;
END
$roles$;

-------------------------------------------------------------------------------
-- 2. Tables (SPEC §3)
-------------------------------------------------------------------------------

-- 3.1 profile
CREATE TABLE profile (
    profile_id        serial PRIMARY KEY,
    name              text NOT NULL UNIQUE
                      CHECK (name ~ '^[A-Za-z0-9_.-]{1,63}$'),
    min_length        int NOT NULL DEFAULT 12  CHECK (min_length >= 8),
    max_length        int NOT NULL DEFAULT 128 CHECK (max_length <= 1024),
    min_lower         int NOT NULL DEFAULT 1   CHECK (min_lower   >= 0),
    min_upper         int NOT NULL DEFAULT 1   CHECK (min_upper   >= 0),
    min_digit         int NOT NULL DEFAULT 1   CHECK (min_digit   >= 0),
    min_special       int NOT NULL DEFAULT 1   CHECK (min_special >= 0),
    min_classes       int NOT NULL DEFAULT 3   CHECK (min_classes BETWEEN 0 AND 4),
    reject_username   bool NOT NULL DEFAULT true,
    reject_dictionary bool NOT NULL DEFAULT true,
    reject_prehashed  bool NOT NULL DEFAULT true,
    max_repeat        int NOT NULL DEFAULT 3   CHECK (max_repeat >= 0),
    history_count     int NOT NULL DEFAULT 5   CHECK (history_count BETWEEN 0 AND 100),
    history_days      int NOT NULL DEFAULT 365 CHECK (history_days >= 0),
    max_age           interval     DEFAULT '90 days' CHECK (max_age > interval '0'),
    min_age           interval NOT NULL DEFAULT '1 day'      CHECK (min_age >= interval '0'),
    grace_period      interval NOT NULL DEFAULT '7 days'     CHECK (grace_period >= interval '0'),
    warn_before       interval NOT NULL DEFAULT '14 days'    CHECK (warn_before >= interval '0'),
    max_failures      int NOT NULL DEFAULT 5   CHECK (max_failures >= 0),
    failure_window    interval NOT NULL DEFAULT '15 minutes' CHECK (failure_window >= interval '0'),  -- 0 = no window (SPEC §11)
    lock_duration     interval     DEFAULT '30 minutes' CHECK (lock_duration > interval '0'),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT profile_length_range CHECK (max_length >= min_length),
    CONSTRAINT profile_classes_fit  CHECK (min_lower + min_upper + min_digit + min_special <= max_length)
);
COMMENT ON TABLE profile IS 'Password policy profiles; "default" applies to every role without an assignment';

-- 3.2 role_profile
CREATE TABLE role_profile (
    role_oid    oid PRIMARY KEY,
    role_name   text NOT NULL,
    profile_id  int NOT NULL REFERENCES profile (profile_id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by text
);
CREATE INDEX role_profile_profile_idx ON role_profile (profile_id);
COMMENT ON TABLE role_profile IS 'Profile assigned to a role (no row = default profile)';

-- 3.3 role_state
CREATE TABLE role_state (
    role_oid            oid PRIMARY KEY,
    role_name           text NOT NULL,
    password_changed_at timestamptz,
    expires_at          timestamptz,
    grace_until         timestamptz,
    last_warned_at      timestamptz,
    locked_until        timestamptz,
    locked_by           text CHECK (locked_by IN ('auto', 'manual')),
    lock_reason         text,
    must_change         bool NOT NULL DEFAULT false,
    valid_until_synced  timestamptz,
    -- Addition to SPEC §3.3: set by record_password_change().  The verifier
    -- computed by the C hook and the one PostgreSQL finally stores in
    -- pg_authid differ (different SCRAM salt); this flag tells
    -- run_maintenance() that the mismatch is expected and that the history
    -- row must simply be replaced by the stored verifier.
    verifier_pending    bool NOT NULL DEFAULT false
);
CREATE INDEX role_state_locked_idx ON role_state (locked_until) WHERE locked_until IS NOT NULL;
COMMENT ON TABLE role_state IS 'Per-role password lifecycle and lock state';

-- 3.4 password_history
CREATE TABLE password_history (
    id         bigserial PRIMARY KEY,
    role_oid   oid,          -- NULL until run_maintenance() maps a role created by CREATE ROLE ... PASSWORD
    role_name  text NOT NULL,
    verifier   text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_history_role_idx ON password_history (role_oid, changed_at DESC);
COMMENT ON TABLE password_history IS 'Previous password verifiers (SCRAM/MD5 hashes, never clear text) for anti-reuse';

-- 3.5 dictionary
CREATE TABLE dictionary (
    word text PRIMARY KEY CHECK (word = lower(word) AND word <> '')
);
COMMENT ON TABLE dictionary IS 'Blocklist of common passwords, stored in lower case';

-- 3.6 audit_log
CREATE TABLE audit_log (
    id               bigserial PRIMARY KEY,
    event_time       timestamptz NOT NULL DEFAULT clock_timestamp(),
    event_type       text NOT NULL CHECK (event_type IN (
                         'password_changed', 'password_rejected', 'auth_failed',
                         'role_locked', 'role_unlocked', 'expiry_warning',
                         'password_expired', 'password_rotated', 'profile_assigned',
                         'profile_changed', 'pair_switched', 'valid_until_synced',
                         'maintenance')),
    role_name        text,
    actor            text,
    database         text,
    client_addr      inet,
    application_name text,
    details          jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_time_idx ON audit_log (event_time);
CREATE INDEX audit_log_role_time_idx ON audit_log (role_name, event_time);
COMMENT ON TABLE audit_log IS 'Audit trail of pg_pass_policy events (never contains passwords or verifiers)';

-- 3.7 rotation_pair
CREATE TABLE rotation_pair (
    pair_name            text PRIMARY KEY,
    role_a               text NOT NULL,
    role_b               text NOT NULL,
    group_role           text NOT NULL,
    active_role          text,
    previous_role        text,
    switched_at          timestamptz,
    previous_valid_until timestamptz,
    CHECK (role_a <> role_b AND role_a <> group_role AND role_b <> group_role),
    CHECK (active_role IS NULL OR active_role IN (role_a, role_b))
);
COMMENT ON TABLE rotation_pair IS 'Zero-downtime rotation pairs: two login roles sharing the privileges of a group role';

-------------------------------------------------------------------------------
-- 2b. Dump/restore support
-------------------------------------------------------------------------------
/*
 * Choice: every configuration table is dumped IN FULL (no WHERE clause) so
 * that a customised "default" profile and user-loaded dictionary words
 * survive pg_dump/pg_restore.  The rows the extension script inserts itself
 * (profile "default", built-in dictionary) would then collide with the
 * dumped copies on restore (CREATE EXTENSION runs first, then COPY), so two
 * BEFORE INSERT triggers make those inserts idempotent:
 *   - profile: a row named 'default' that already exists updates the
 *     existing row (settings of the dump win) instead of being inserted ;
 *   - dictionary: words are lower-cased and duplicates are silently skipped.
 * Caveat: a data-only restore with --disable-triggers bypasses this.
 * Role OIDs differ between clusters: run_maintenance() re-maps role_oid by
 * role name (pg_dumpall --globals restores the roles by name).
 */
CREATE FUNCTION _profile_restore_trg() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
BEGIN
    IF NEW.name = 'default' AND EXISTS (SELECT FROM pass_policy.profile p WHERE p.name = 'default') THEN
        UPDATE pass_policy.profile p
           SET (min_length, max_length, min_lower, min_upper, min_digit, min_special,
                min_classes, reject_username, reject_dictionary, reject_prehashed,
                max_repeat, history_count, history_days, max_age, min_age,
                grace_period, warn_before, max_failures, failure_window,
                lock_duration, created_at, updated_at)
             = (NEW.min_length, NEW.max_length, NEW.min_lower, NEW.min_upper, NEW.min_digit, NEW.min_special,
                NEW.min_classes, NEW.reject_username, NEW.reject_dictionary, NEW.reject_prehashed,
                NEW.max_repeat, NEW.history_count, NEW.history_days, NEW.max_age, NEW.min_age,
                NEW.grace_period, NEW.warn_before, NEW.max_failures, NEW.failure_window,
                NEW.lock_duration, NEW.created_at, NEW.updated_at)
         WHERE p.name = 'default';
        RETURN NULL;
    END IF;
    RETURN NEW;
END
$$;
COMMENT ON FUNCTION _profile_restore_trg() IS 'Internal: makes re-inserting the default profile (pg_restore) update it instead of failing';
CREATE TRIGGER profile_restore BEFORE INSERT ON profile
    FOR EACH ROW EXECUTE FUNCTION _profile_restore_trg();

CREATE FUNCTION _dictionary_trg() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
BEGIN
    NEW.word := lower(btrim(NEW.word));
    IF NEW.word = '' OR EXISTS (SELECT FROM pass_policy.dictionary d WHERE d.word = NEW.word) THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END
$$;
COMMENT ON FUNCTION _dictionary_trg() IS 'Internal: lower-cases dictionary words and skips duplicates';
CREATE TRIGGER dictionary_normalize BEFORE INSERT ON dictionary
    FOR EACH ROW EXECUTE FUNCTION _dictionary_trg();

SELECT pg_catalog.pg_extension_config_dump('profile', '');
SELECT pg_catalog.pg_extension_config_dump('profile_profile_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('role_profile', '');
SELECT pg_catalog.pg_extension_config_dump('role_state', '');
SELECT pg_catalog.pg_extension_config_dump('password_history', '');
SELECT pg_catalog.pg_extension_config_dump('password_history_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('dictionary', '');
SELECT pg_catalog.pg_extension_config_dump('rotation_pair', '');
SELECT pg_catalog.pg_extension_config_dump('audit_log', '');
SELECT pg_catalog.pg_extension_config_dump('audit_log_id_seq', '');

-------------------------------------------------------------------------------
-- 3. Built-in data
-------------------------------------------------------------------------------
INSERT INTO profile (name) VALUES ('default');   -- all values = column defaults (SPEC §3.1)

INSERT INTO dictionary (word) VALUES
-- generic top lists (SecLists / NCSC / NordPass style)
('123456'),('1234567'),('12345678'),('123456789'),('1234567890'),('12345678910'),
('123123'),('123123123'),('111111'),('11111111'),('000000'),('00000000'),('654321'),
('987654321'),('121212'),('112233'),('123321'),('666666'),('888888'),('7777777'),
('159753'),('147258369'),('123654'),('1q2w3e'),('1q2w3e4r'),('1q2w3e4r5t'),
('1qaz2wsx'),('1qaz2wsx3edc'),('zaq12wsx'),('qazwsx'),('qazwsxedc'),('q1w2e3r4'),
('q1w2e3r4t5'),('a1b2c3'),('abc123'),('abc12345'),('abcd1234'),('abcdef'),
('aa123456'),('password'),('password1'),('password12'),('password123'),
('password1234'),('password!'),('p@ssw0rd'),('p@ssword'),('passw0rd'),('pass123'),
('pass1234'),('passpass'),('motdepasse'),('motdepasse1'),('motdepasse123'),
('mot2passe'),('azerty'),('azerty1'),('azerty12'),('azerty123'),('azerty1234'),
('azertyuiop'),('azertyuiop123'),('azertyui'),('qsdfghjklm'),('wxcvbn'),
('qwerty'),('qwerty1'),('qwerty12'),('qwerty123'),('qwerty1234'),('qwertyuiop'),
('qwertyui'),('asdfgh'),('asdfghjkl'),('asdf1234'),('zxcvbn'),('zxcvbnm'),
('qweasd'),('qweasdzxc'),('qwe123'),('1qazxsw2'),('iloveyou'),('iloveyou1'),
('jetaime'),('princess'),('sunshine'),('monkey'),('dragon'),('football'),
('baseball'),('soccer'),('hockey'),('superman'),('batman'),('pokemon'),
('starwars'),('master'),('shadow'),('michael'),('jennifer'),('jordan23'),
('liverpool'),('chelsea'),('arsenal'),('marseille'),('olympique'),('doudou'),
('chouchou'),('loulou'),('soleil'),('nicolas'),('camille'),('thomas'),
('welcome'),('welcome1'),('welcome123'),('bienvenue'),('bienvenue1'),('hello'),
('hello123'),('letmein'),('letmein1'),('trustno1'),('whatever'),('freedom'),
('computer'),('internet'),('google'),('samsung'),('charlie'),('flower'),
('cookie'),('cheese'),('pepper'),('ginger'),('killer'),('ninja'),('mustang'),
('access'),('access123'),('login'),('login123'),('guest'),('guest123'),
('test'),('test123'),('test1234'),('testtest'),('demo'),('demo123'),
('user'),('user123'),('default'),('changeme'),('changeme1'),('changeme123'),
('change_me'),('secret'),('secret123'),('topsecret'),('nopassword'),
('admin'),('admin1'),('admin12'),('admin123'),('admin1234'),('admin@123'),
('administrator'),('administrateur'),('root'),('root123'),('toor'),('rootroot'),
('superuser'),('sysadmin'),('system'),('manager'),('oracle'),('mysql'),
('postgres'),('postgres1'),('postgres123'),('postgresql'),('postgresql1'),
('pgadmin'),('pgsql'),('database'),('database1'),('database123'),('db2admin'),
('dbadmin'),('sa'),('server'),('backup'),('replication'),('replicator'),
('monitor'),('monitoring'),('service'),('support'),('master123'),('qwerty!'),
('azerty!'),('aaaaaa'),('abcabc'),('a123456'),('123456a'),('123456789a'),
-- seasons + year (FR/EN)
('printemps2023'),('ete2023'),('automne2023'),('hiver2023'),
('spring2023'),('summer2023'),('autumn2023'),('winter2023'),
('printemps2024'),('ete2024'),('automne2024'),('hiver2024'),
('spring2024'),('summer2024'),('autumn2024'),('winter2024'),
('printemps2025'),('ete2025'),('automne2025'),('hiver2025'),
('spring2025'),('summer2025'),('autumn2025'),('winter2025'),
('printemps2026'),('ete2026'),('automne2026'),('hiver2026'),
('spring2026'),('summer2026'),('autumn2026'),('winter2026'),
('printemps2027'),('ete2027'),('automne2027'),('hiver2027'),
('spring2027'),('summer2027'),('autumn2027'),('winter2027');

-------------------------------------------------------------------------------
-- 4. C functions (SPEC §4, symbols in src/*.c)
-------------------------------------------------------------------------------
CREATE FUNCTION check_password(role text, password text)
RETURNS text
AS 'MODULE_PATHNAME', 'ppp_check_password'
LANGUAGE C STRICT STABLE PARALLEL RESTRICTED;
COMMENT ON FUNCTION check_password(text, text) IS 'Checks a candidate password against the effective profile of a role; NULL if compliant, else a PPP-xxx reason';

-- Not STRICT: profile may be NULL (= profile "default"); length NULL = 24.
CREATE FUNCTION generate_password(length int DEFAULT 24, profile text DEFAULT NULL)
RETURNS text
AS 'MODULE_PATHNAME', 'ppp_generate_password'
LANGUAGE C VOLATILE PARALLEL RESTRICTED;
COMMENT ON FUNCTION generate_password(int, text) IS 'Generates a random password (pg_strong_random) compliant with a profile';

CREATE FUNCTION failed_attempts()
RETURNS TABLE (role_name text, failed_count int, first_failure_at timestamptz,
               last_failure_at timestamptz, locked_until timestamptz)
AS 'MODULE_PATHNAME', 'ppp_failed_attempts'
LANGUAGE C VOLATILE PARALLEL SAFE;
COMMENT ON FUNCTION failed_attempts() IS 'Authentication failure counters and locks held in shared memory';

CREATE FUNCTION shmem_reload()
RETURNS void
AS 'MODULE_PATHNAME', 'ppp_shmem_reload'
LANGUAGE C VOLATILE;
COMMENT ON FUNCTION shmem_reload() IS 'Asks the worker to reload lockout parameters into shared memory';

-- Not STRICT: until NULL = manual lock (DT_NOEND).
CREATE FUNCTION shmem_lock_role(role text, until timestamptz DEFAULT NULL)
RETURNS void
AS 'MODULE_PATHNAME', 'ppp_shmem_lock_role'
LANGUAGE C VOLATILE;
COMMENT ON FUNCTION shmem_lock_role(text, timestamptz) IS 'Locks a role in shared memory until a timestamp (NULL = until manual unlock)';

CREATE FUNCTION shmem_unlock_role(role text)
RETURNS void
AS 'MODULE_PATHNAME', 'ppp_shmem_unlock_role'
LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION shmem_unlock_role(text) IS 'Removes the shared-memory lock of a role';

CREATE FUNCTION shmem_reset_failures(role text)
RETURNS void
AS 'MODULE_PATHNAME', 'ppp_shmem_reset_failures'
LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION shmem_reset_failures(text) IS 'Resets the shared-memory failure counter of a role';

CREATE FUNCTION worker_status()
RETURNS TABLE (pid int, last_run timestamptz, last_reload timestamptz, tracked_roles int)
AS 'MODULE_PATHNAME', 'ppp_worker_status'
LANGUAGE C VOLATILE PARALLEL SAFE;
COMMENT ON FUNCTION worker_status() IS 'State of the pg_pass_policy background worker';

/*
 * Addition to SPEC §4: true only while this backend is executing the
 * pg_pass_policy check_password_hook (static flag set by the C hook around
 * its SPI calls).  record_password_change() and audit() are callable by
 * PUBLIC because the hook runs in the session of whoever issues
 * ALTER/CREATE ROLE ... PASSWORD; without this guard any user could call
 * record_password_change() on himself and push back his own expiry without
 * changing his password.
 */
CREATE FUNCTION _in_password_hook()
RETURNS bool
AS 'MODULE_PATHNAME', 'ppp_in_password_hook'
LANGUAGE C VOLATILE PARALLEL RESTRICTED;
COMMENT ON FUNCTION _in_password_hook() IS 'Internal: true while the pg_pass_policy password hook is running in this backend';

-------------------------------------------------------------------------------
-- 5. Internal helpers
-------------------------------------------------------------------------------

-- Effective profile of every existing role (internal, used by views and maintenance).
CREATE VIEW _role_effective_profile AS
SELECT a.oid AS role_oid, a.rolname::text AS role_name, p.*
  FROM pg_catalog.pg_authid a
  LEFT JOIN role_profile rp ON rp.role_oid = a.oid
  JOIN profile p ON p.profile_id = coalesce(rp.profile_id,
                       (SELECT d.profile_id FROM profile d WHERE d.name = 'default'));
COMMENT ON VIEW _role_effective_profile IS 'Internal: effective profile of every role';

CREATE FUNCTION _is_admin()
RETURNS bool
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT coalesce((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user), false)
        OR pg_catalog.pg_has_role(session_user, 'pass_policy_admin', 'MEMBER')
$$;
COMMENT ON FUNCTION _is_admin() IS 'Internal: true if session_user is a superuser or a member of pass_policy_admin';

CREATE FUNCTION _require_admin()
RETURNS void
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT coalesce(pass_policy._is_admin(), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied'
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'Superuser or membership in pass_policy_admin is required.';
    END IF;
END
$$;
COMMENT ON FUNCTION _require_admin() IS 'Internal: raises an error unless session_user is a superuser or a pass_policy_admin member';

/*
 * A member of pass_policy_admin who is not superuser must not be able to
 * take over a more privileged role by rotating/expiring/locking it, nor to
 * grant such a role to the login roles of a rotation pair.  A role is
 * privileged when it has SUPERUSER, REPLICATION or BYPASSRLS, when it is a
 * predefined pg_* role (pg_execute_server_program runs OS commands,
 * pg_write_server_files writes any server file...; pg_database_owner is
 * excluded: every database owner is an implicit member and it carries no
 * privilege beyond the ownership already held), when it is a member, even
 * indirectly, of such a role (SET ROLE / INHERIT give its privileges), or,
 * on PostgreSQL <= 15, when it has CREATEROLE (which could then grant pg_*
 * roles and change the password of any non-superuser).
 */
CREATE FUNCTION _require_target_allowed(p_role name)
RETURNS oid
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    r record;
BEGIN
    SELECT a.oid, a.rolname, a.rolsuper, a.rolreplication, a.rolbypassrls, a.rolcreaterole INTO r
      FROM pg_catalog.pg_authid a WHERE a.rolname = p_role;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: role "%" does not exist', p_role
              USING ERRCODE = 'undefined_object';
    END IF;
    IF coalesce((SELECT x.rolsuper FROM pg_catalog.pg_roles x WHERE x.rolname = session_user), false) THEN
        RETURN r.oid;
    END IF;
    IF r.rolsuper OR r.rolreplication OR r.rolbypassrls
       OR (starts_with(r.rolname, 'pg_') AND r.rolname <> 'pg_database_owner')
       OR (r.rolcreaterole AND current_setting('server_version_num')::int < 160000)
       OR EXISTS (SELECT FROM pg_catalog.pg_authid x
                   WHERE x.oid <> r.oid
                     AND (x.rolsuper OR x.rolreplication OR x.rolbypassrls
                          OR (starts_with(x.rolname, 'pg_') AND x.rolname <> 'pg_database_owner'))
                     AND pg_catalog.pg_has_role(r.oid, x.oid, 'MEMBER')) THEN
        RAISE EXCEPTION 'pg_pass_policy: only a superuser can manage privileged role "%"', p_role
              USING ERRCODE = 'insufficient_privilege',
                    DETAIL = 'The role has, or is a member of a role having, SUPERUSER, REPLICATION, BYPASSRLS or predefined (pg_*) privileges.';
    END IF;
    RETURN r.oid;
END
$$;
COMMENT ON FUNCTION _require_target_allowed(name) IS 'Internal: returns the role OID; refuses privileged targets (directly or by membership) for non-superusers';

CREATE FUNCTION _guc_on(p_name text, p_default bool)
RETURNS bool
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT CASE lower(coalesce(current_setting(p_name, true), ''))
               WHEN '' THEN p_default
               WHEN 'on' THEN true WHEN 'true' THEN true WHEN 'yes' THEN true WHEN '1' THEN true
               ELSE false END
$$;
COMMENT ON FUNCTION _guc_on(text, bool) IS 'Internal: reads a boolean GUC, with a default when it is undefined';

CREATE FUNCTION _is_exempt(p_role text)
RETURNS bool
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p_role = ANY (string_to_array(
               replace(coalesce(current_setting('pg_pass_policy.exempt_roles', true), ''), ' ', ''), ','))
$$;
COMMENT ON FUNCTION _is_exempt(text) IS 'Internal: true if the role is listed in pass_policy.exempt_roles';

-- Calls to the C shared-memory functions must never break maintenance or
-- administration when the library/worker is unavailable: errors become WARNINGs.
CREATE FUNCTION _shmem(p_op text, p_role text DEFAULT NULL, p_until timestamptz DEFAULT NULL)
RETURNS bool
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    CASE p_op
        WHEN 'reload' THEN PERFORM pass_policy.shmem_reload();
        WHEN 'lock'   THEN PERFORM pass_policy.shmem_lock_role(p_role, p_until);
        WHEN 'unlock' THEN PERFORM pass_policy.shmem_unlock_role(p_role);
        WHEN 'reset'  THEN PERFORM pass_policy.shmem_reset_failures(p_role);
    END CASE;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'pg_pass_policy: shared memory call "%" failed: %', p_op, SQLERRM;
    RETURN false;
END
$$;
COMMENT ON FUNCTION _shmem(text, text, timestamptz) IS 'Internal: calls a shmem_* C function, downgrading failures to warnings';

-- Internal audit writer (no permission check: only called by trusted code).
CREATE FUNCTION _audit(p_event_type text, p_role_name text, p_details jsonb DEFAULT '{}')
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_actor   text := session_user;
    v_time    timestamptz;
    v_details jsonb := coalesce(p_details, '{}');
    v_payload text;
BEGIN
    -- SPEC §11: actor = 'worker' when called by the background worker
    BEGIN
        IF pg_catalog.pg_backend_pid() = (SELECT w.pid FROM pass_policy.worker_status() w LIMIT 1) THEN
            v_actor := 'worker';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        NULL;   -- library/shmem unavailable: keep session_user
    END;

    INSERT INTO pass_policy.audit_log
           (event_type, role_name, actor, database, client_addr, application_name, details)
    VALUES (p_event_type, p_role_name, v_actor, current_database(), inet_client_addr(),
            current_setting('application_name', true), v_details)
    RETURNING event_time INTO v_time;

    v_payload := jsonb_build_object('event', p_event_type, 'role', p_role_name,
                                    'at', v_time, 'details', v_details)::text;
    IF octet_length(v_payload) > 7900 THEN      -- NOTIFY payload limit is 8000 bytes
        v_payload := jsonb_build_object('event', p_event_type, 'role', p_role_name,
                                        'at', v_time, 'details', jsonb_build_object('truncated', true))::text;
    END IF;
    PERFORM pg_notify(coalesce(nullif(current_setting('pg_pass_policy.notify_channel', true), ''),
                               'pg_pass_policy'),
                      v_payload);

    IF pass_policy._guc_on('pg_pass_policy.log_events', true) THEN
        RAISE LOG 'pg_pass_policy: % role=% %', p_event_type, coalesce(p_role_name, '-'), v_details::text;
    END IF;
END
$$;
COMMENT ON FUNCTION _audit(text, text, jsonb) IS 'Internal: writes an audit row, sends NOTIFY and logs';

-- Recomputes expires_at / grace_until from the effective profile
-- (rows with must_change keep the values set by expire_password()).
CREATE FUNCTION _refresh_role_state(p_oid oid DEFAULT NULL)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
DECLARE
    n int;
BEGIN
    UPDATE pass_policy.role_state s
       SET expires_at  = c.new_expires,
           grace_until = c.new_expires + c.grace_period
      FROM (SELECT e.role_oid, e.grace_period,
                   CASE WHEN e.max_age IS NULL OR s2.password_changed_at IS NULL THEN NULL
                        ELSE s2.password_changed_at + e.max_age END AS new_expires
              FROM pass_policy._role_effective_profile e
              JOIN pass_policy.role_state s2 ON s2.role_oid = e.role_oid) c
     WHERE c.role_oid = s.role_oid
       AND NOT s.must_change
       AND (p_oid IS NULL OR s.role_oid = p_oid)
       AND (s.expires_at IS DISTINCT FROM c.new_expires
            OR s.grace_until IS DISTINCT FROM c.new_expires + c.grace_period);
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
COMMENT ON FUNCTION _refresh_role_state(oid) IS 'Internal: recomputes expires_at and grace_until from the effective profile';

/*
 * Synchronises pg_authid.rolvaliduntil of one role with role_state.
 * p_mode:
 *   'sync'    maintenance: desired = grace_until (bounded by a rotation pair);
 *             NULL -> 'infinity' only if the current value was written by us;
 *             never overrides a shorter value set manually ;
 *   'force'   rotation: always writes coalesce(desired, 'infinity') ;
 *   'unblock' rotation with manage_valid_until = off: writes only if the
 *             current VALID UNTIL is already in the past.
 * Returns a jsonb description of the change, or NULL if nothing was done.
 */
CREATE FUNCTION _apply_valid_until(p_oid oid, p_mode text DEFAULT 'sync')
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
DECLARE
    r        record;
    v_desired timestamptz;
    v_new    timestamptz;
BEGIN
    SELECT a.rolname, a.rolvaliduntil, s.grace_until, s.valid_until_synced,
           (SELECT min(rp.previous_valid_until) FROM pass_policy.rotation_pair rp
             WHERE rp.previous_role = a.rolname AND rp.previous_valid_until IS NOT NULL) AS pair_bound
      INTO r
      FROM pg_catalog.pg_authid a
      JOIN pass_policy.role_state s ON s.role_oid = a.oid
     WHERE a.oid = p_oid;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    v_desired := least(r.grace_until, r.pair_bound);   -- least() ignores NULLs

    IF p_mode = 'force' THEN
        v_new := coalesce(v_desired, 'infinity');
    ELSIF p_mode = 'unblock' THEN
        IF r.rolvaliduntil IS NULL OR r.rolvaliduntil > now() THEN
            RETURN NULL;
        END IF;
        v_new := coalesce(v_desired, 'infinity');
    ELSE
        IF v_desired IS NULL THEN
            IF r.rolvaliduntil IS NULL OR r.rolvaliduntil = 'infinity' THEN
                RETURN NULL;
            END IF;
            -- only undo a value that we wrote ourselves
            IF r.valid_until_synced IS NULL OR r.rolvaliduntil <> r.valid_until_synced THEN
                RETURN NULL;
            END IF;
            v_new := 'infinity';
        ELSE
            IF r.rolvaliduntil = v_desired THEN
                RETURN NULL;
            END IF;
            -- a shorter VALID UNTIL set manually is respected
            IF r.rolvaliduntil IS NOT NULL AND r.rolvaliduntil < v_desired
               AND r.rolvaliduntil IS DISTINCT FROM r.valid_until_synced THEN
                RETURN NULL;
            END IF;
            v_new := v_desired;
        END IF;
    END IF;

    IF r.rolvaliduntil IS NOT DISTINCT FROM v_new THEN
        UPDATE pass_policy.role_state s
           SET valid_until_synced = CASE WHEN v_new = 'infinity' THEN NULL ELSE v_new END
         WHERE s.role_oid = p_oid;
        RETURN NULL;
    END IF;

    EXECUTE format('ALTER ROLE %I VALID UNTIL %L', r.rolname, v_new);
    UPDATE pass_policy.role_state s
       SET valid_until_synced = CASE WHEN v_new = 'infinity' THEN NULL ELSE v_new END
     WHERE s.role_oid = p_oid;
    RETURN jsonb_build_object('old', r.rolvaliduntil, 'new', v_new, 'mode', p_mode);
END
$$;
COMMENT ON FUNCTION _apply_valid_until(oid, text) IS 'Internal: writes VALID UNTIL of a role according to its role_state';

/*
 * Executes ALTER ROLE ... PASSWORD with a generated password.
 * - pg_stat_statements.track_utility is switched off locally (if the module
 *   is loaded) so the statement text is not stored ;
 * - log_error_verbosity = terse and log_min_error_statement = panic for the
 *   whole function: any message written to the server log meanwhile (RAISE
 *   LOG of the audit, a PPP-xxx ERROR raised by the hook, which is logged
 *   when raised even if caught below) carries neither CONTEXT nor STATEMENT,
 *   both of which would contain the ALTER ROLE text, hence the password ;
 * - an error is re-raised WITHOUT its CONTEXT (which would contain the
 *   statement text, hence the password) ;
 * - this statement is nested, so log_statement never logs it ;
 * - auto_explain (log_nested_statements = on) is silenced for the duration
 *   of the function: with log_verbose it would print the parameters of the
 *   nested statements of the hook (the SCRAM verifier of the new password).
 * The set_config(..., true) calls are made outside the inner block so that
 * they survive its subtransaction rollback; they are undone at function exit
 * (the function has a SET clause, so its GUC nesting level is restored).
 * Callers are SECURITY DEFINER functions owned by a superuser, which allows
 * setting these superuser-only parameters.
 */
CREATE FUNCTION _set_password(p_role name, p_password text)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_pgss    text := current_setting('pg_stat_statements.track_utility', true);
    v_state   text;
    v_msg     text;
    v_detail  text;
    v_hint    text;
BEGIN
    PERFORM set_config('log_error_verbosity', 'terse', true);
    PERFORM set_config('log_min_error_statement', 'panic', true);
    IF current_setting('auto_explain.log_min_duration', true) IS NOT NULL THEN
        PERFORM set_config('auto_explain.log_min_duration', '-1', true);
    END IF;
    IF v_pgss IS NOT NULL THEN
        PERFORM set_config('pg_stat_statements.track_utility', 'off', true);
    END IF;
    BEGIN
        EXECUTE format('ALTER ROLE %I PASSWORD %L', p_role, p_password);
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT,
                                v_detail = PG_EXCEPTION_DETAIL, v_hint = PG_EXCEPTION_HINT;
        IF v_pgss IS NOT NULL THEN
            PERFORM set_config('pg_stat_statements.track_utility', v_pgss, true);
        END IF;
        RAISE EXCEPTION USING ERRCODE = v_state, MESSAGE = v_msg,
              DETAIL = coalesce(v_detail, ''), HINT = coalesce(v_hint, '');
    END;
    IF v_pgss IS NOT NULL THEN
        PERFORM set_config('pg_stat_statements.track_utility', v_pgss, true);
    END IF;
END
$$;
COMMENT ON FUNCTION _set_password(name, text) IS 'Internal: ALTER ROLE PASSWORD without leaking the password in logs or error context';

-- Records a password change (no permission check: trusted callers only).
CREATE FUNCTION _record_password_change(p_role text, p_verifier text)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
DECLARE
    v_oid  oid;
    p      pass_policy.profile;
BEGIN
    IF p_role IS NULL OR p_verifier IS NULL THEN
        RETURN;
    END IF;
    SELECT a.oid INTO v_oid FROM pg_catalog.pg_authid a WHERE a.rolname = p_role;
    SELECT * INTO p FROM pass_policy.effective_profile(p_role::name);

    IF v_oid IS NULL THEN
        -- CREATE ROLE ... PASSWORD: the hook runs before the role exists.
        -- run_maintenance() maps the row to the new OID and creates role_state.
        INSERT INTO pass_policy.password_history (role_oid, role_name, verifier, changed_at)
        VALUES (NULL, p_role, p_verifier, now());
        PERFORM pass_policy._audit('password_changed', p_role,
                jsonb_build_object('profile', p.name, 'new_role', true));
        RETURN;
    END IF;

    INSERT INTO pass_policy.password_history (role_oid, role_name, verifier, changed_at)
    VALUES (v_oid, p_role, p_verifier, now());

    -- keep history_count entries (at least one: the reference for reconciliation)
    DELETE FROM pass_policy.password_history h
     WHERE h.role_oid = v_oid
       AND h.id NOT IN (SELECT h2.id FROM pass_policy.password_history h2
                         WHERE h2.role_oid = v_oid
                         ORDER BY h2.changed_at DESC, h2.id DESC
                         LIMIT greatest(p.history_count, 1));

    INSERT INTO pass_policy.role_state AS s
           (role_oid, role_name, password_changed_at, expires_at, grace_until,
            last_warned_at, must_change, verifier_pending)
    VALUES (v_oid, p_role, now(), now() + p.max_age, now() + p.max_age + p.grace_period,
            NULL, false, true)
    ON CONFLICT (role_oid) DO UPDATE
       SET role_name           = EXCLUDED.role_name,
           password_changed_at = EXCLUDED.password_changed_at,
           expires_at          = EXCLUDED.expires_at,
           grace_until         = EXCLUDED.grace_until,
           last_warned_at      = NULL,
           must_change         = false,
           verifier_pending    = true;

    PERFORM pass_policy._audit('password_changed', p_role, jsonb_build_object('profile', p.name));
END
$$;
COMMENT ON FUNCTION _record_password_change(text, text) IS 'Internal: stores a verifier in the history and updates role_state';

-- After an ALTER ROLE ... PASSWORD issued by the extension itself, makes sure
-- the change is recorded even if the hook did not run (exempt role,
-- pass_policy.enabled = off, ...).
CREATE FUNCTION _ensure_recorded(p_role name)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_oid oid;
    v_ver text;
BEGIN
    SELECT a.oid, a.rolpassword INTO v_oid, v_ver FROM pg_catalog.pg_authid a WHERE a.rolname = p_role;
    IF NOT EXISTS (SELECT FROM pass_policy.role_state s
                    WHERE s.role_oid = v_oid AND s.password_changed_at = now() AND s.verifier_pending) THEN
        PERFORM pass_policy._record_password_change(p_role::text, v_ver);
    END IF;
END
$$;
COMMENT ON FUNCTION _ensure_recorded(name) IS 'Internal: records a password change if the C hook did not';

-- Creates the role_state row of an existing role if missing.
CREATE FUNCTION _ensure_state(p_oid oid)
RETURNS void
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO pass_policy.role_state (role_oid, role_name)
    SELECT a.oid, a.rolname FROM pg_catalog.pg_authid a WHERE a.oid = p_oid
    ON CONFLICT (role_oid) DO NOTHING
$$;
COMMENT ON FUNCTION _ensure_state(oid) IS 'Internal: creates the role_state row of a role if missing';

-- Validates a jsonb settings object and applies it to a profile.
CREATE FUNCTION _apply_profile_settings(p_profile_id int, p_settings jsonb)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pass_policy, pg_temp
AS $$
DECLARE
    v_allowed text[] := ARRAY['min_length', 'max_length', 'min_lower', 'min_upper', 'min_digit',
                              'min_special', 'min_classes', 'reject_username', 'reject_dictionary',
                              'reject_prehashed', 'max_repeat', 'history_count', 'history_days',
                              'max_age', 'min_age', 'grace_period', 'warn_before', 'max_failures',
                              'failure_window', 'lock_duration'];
    v_keys    text[];
    v_bad     text[];
    v_cols    text;
BEGIN
    IF p_settings IS NULL OR p_settings = '{}'::jsonb THEN
        RETURN;
    END IF;
    IF jsonb_typeof(p_settings) <> 'object' THEN
        RAISE EXCEPTION 'pg_pass_policy: settings must be a JSON object'
              USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT array_agg(k ORDER BY k) INTO v_keys FROM jsonb_object_keys(p_settings) AS k;
    SELECT array_agg(k) INTO v_bad FROM unnest(v_keys) AS k WHERE k <> ALL (v_allowed);
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'pg_pass_policy: unknown profile setting(s): %', array_to_string(v_bad, ', ')
              USING ERRCODE = 'invalid_parameter_value',
                    HINT = 'Allowed keys: ' || array_to_string(v_allowed, ', ');
    END IF;
    -- jsonb_populate_record() does the typing (int, bool, interval; JSON null -> NULL)
    SELECT string_agg(format('%I', k), ', ') INTO v_cols FROM unnest(v_keys) AS k;
    EXECUTE format('UPDATE pass_policy.profile p SET (%s, updated_at) = '
                   '(SELECT %s, now() FROM jsonb_populate_record(NULL::pass_policy.profile, $1)) '
                   'WHERE p.profile_id = $2', v_cols, v_cols)
      USING p_settings, p_profile_id;
END
$$;
COMMENT ON FUNCTION _apply_profile_settings(int, jsonb) IS 'Internal: validates and applies jsonb settings to a profile';

-------------------------------------------------------------------------------
-- 6. Public API (SPEC §4)
-------------------------------------------------------------------------------

-- audit(): callable by PUBLIC so that the C hook can log password_rejected
-- from the session of the user; outside the hook only admins may write.
CREATE FUNCTION audit(event_type text, role_name text, details jsonb DEFAULT '{}')
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT coalesce(pass_policy._is_admin() OR pass_policy._in_password_hook(), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied'
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'audit() may only be called by an administrator or by the password hook.';
    END IF;
    PERFORM pass_policy._audit($1, $2, $3);
END
$$;
COMMENT ON FUNCTION audit(text, text, jsonb) IS 'Writes an audit event (table + NOTIFY + LOG)';

CREATE FUNCTION effective_profile(role name)
RETURNS SETOF profile
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p.*
      FROM pass_policy.profile p
     WHERE p.profile_id = coalesce(
             (SELECT rp.profile_id
                FROM pass_policy.role_profile rp
                JOIN pg_catalog.pg_authid a ON a.oid = rp.role_oid
               WHERE a.rolname = $1),
             (SELECT d.profile_id FROM pass_policy.profile d WHERE d.name = 'default'))
$$;
COMMENT ON FUNCTION effective_profile(name) IS 'Profile applying to a role (assigned profile or "default")';

/*
 * Called by the C hook (SPI) after a password has been accepted, in the
 * session of whoever runs CREATE/ALTER ROLE ... PASSWORD, hence
 * SECURITY DEFINER + EXECUTE to PUBLIC.  Allowed when:
 *  - the backend is inside the pg_pass_policy hook (_in_password_hook()):
 *    PostgreSQL has already checked that the current user may set this
 *    role's password (CREATEROLE/ADMIN, self, superuser) before calling the
 *    hook ; or
 *  - session_user is a superuser or a pass_policy_admin member.
 * A plain user calling it directly for himself is refused: otherwise he
 * could reset his own expiry without changing his password.
 */
CREATE FUNCTION record_password_change(role text, verifier text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT coalesce(pass_policy._in_password_hook() OR pass_policy._is_admin(), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied to record a password change for role "%"', $1
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'Change the password with ALTER ROLE ... PASSWORD.';
    END IF;
    PERFORM pass_policy._record_password_change($1, $2);
END
$$;
COMMENT ON FUNCTION record_password_change(text, text) IS 'Records an accepted password change (called by the C password hook)';

CREATE FUNCTION create_profile(name text, settings jsonb DEFAULT '{}')
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_name text := $1;
    v_id   int;
BEGIN
    PERFORM pass_policy._require_admin();
    IF EXISTS (SELECT FROM pass_policy.profile p WHERE p.name = v_name) THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "%" already exists', v_name
              USING ERRCODE = 'duplicate_object';
    END IF;
    INSERT INTO pass_policy.profile (name) VALUES (v_name) RETURNING profile_id INTO v_id;
    PERFORM pass_policy._apply_profile_settings(v_id, $2);
    PERFORM pass_policy._audit('profile_changed', NULL,
            jsonb_build_object('action', 'create', 'profile', v_name, 'settings', coalesce($2, '{}')));
    PERFORM pass_policy._shmem('reload');
    RETURN v_id;
END
$$;
COMMENT ON FUNCTION create_profile(text, jsonb) IS 'Creates a password profile from jsonb settings (keys = profile columns)';

CREATE FUNCTION alter_profile(name text, settings jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_name text := $1;
    v_id   int;
BEGIN
    PERFORM pass_policy._require_admin();
    SELECT p.profile_id INTO v_id FROM pass_policy.profile p WHERE p.name = v_name FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "%" does not exist', v_name
              USING ERRCODE = 'undefined_object';
    END IF;
    PERFORM pass_policy._apply_profile_settings(v_id, $2);
    PERFORM pass_policy._refresh_role_state(NULL);
    PERFORM pass_policy._audit('profile_changed', NULL,
            jsonb_build_object('action', 'alter', 'profile', v_name, 'settings', coalesce($2, '{}')));
    PERFORM pass_policy._shmem('reload');
END
$$;
COMMENT ON FUNCTION alter_profile(text, jsonb) IS 'Changes settings of a password profile';

CREATE FUNCTION drop_profile(name text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_name text := $1;
    v_id   int;
    v_n    bigint;
BEGIN
    PERFORM pass_policy._require_admin();
    IF v_name = 'default' THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "default" cannot be dropped'
              USING ERRCODE = 'object_in_use';
    END IF;
    SELECT p.profile_id INTO v_id FROM pass_policy.profile p WHERE p.name = v_name FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "%" does not exist', v_name
              USING ERRCODE = 'undefined_object';
    END IF;
    SELECT count(*) INTO v_n FROM pass_policy.role_profile rp WHERE rp.profile_id = v_id;
    IF v_n > 0 THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "%" is assigned to % role(s)', v_name, v_n
              USING ERRCODE = 'object_in_use',
                    HINT = 'Use unassign_profile() first.';
    END IF;
    DELETE FROM pass_policy.profile p WHERE p.profile_id = v_id;
    PERFORM pass_policy._audit('profile_changed', NULL,
            jsonb_build_object('action', 'drop', 'profile', v_name));
END
$$;
COMMENT ON FUNCTION drop_profile(text) IS 'Drops an unassigned profile (default cannot be dropped)';

CREATE FUNCTION assign_profile(role name, profile text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role name := $1;
    v_oid  oid;
    v_pid  int;
BEGIN
    PERFORM pass_policy._require_admin();
    SELECT a.oid INTO v_oid FROM pg_catalog.pg_authid a WHERE a.rolname = v_role;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: role "%" does not exist', v_role
              USING ERRCODE = 'undefined_object';
    END IF;
    SELECT p.profile_id INTO v_pid FROM pass_policy.profile p WHERE p.name = $2;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: profile "%" does not exist', $2
              USING ERRCODE = 'undefined_object';
    END IF;
    INSERT INTO pass_policy.role_profile AS rp (role_oid, role_name, profile_id, assigned_at, assigned_by)
    VALUES (v_oid, v_role, v_pid, now(), session_user)
    ON CONFLICT (role_oid) DO UPDATE
       SET role_name = EXCLUDED.role_name, profile_id = EXCLUDED.profile_id,
           assigned_at = EXCLUDED.assigned_at, assigned_by = EXCLUDED.assigned_by;
    PERFORM pass_policy._refresh_role_state(v_oid);
    PERFORM pass_policy._audit('profile_assigned', v_role, jsonb_build_object('profile', $2));
    PERFORM pass_policy._shmem('reload');
END
$$;
COMMENT ON FUNCTION assign_profile(name, text) IS 'Assigns a password profile to a role';

CREATE FUNCTION unassign_profile(role name)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role name := $1;
    v_oid  oid;
BEGIN
    PERFORM pass_policy._require_admin();
    SELECT a.oid INTO v_oid FROM pg_catalog.pg_authid a WHERE a.rolname = v_role;
    DELETE FROM pass_policy.role_profile rp
     WHERE rp.role_oid = v_oid OR (v_oid IS NULL AND rp.role_name = v_role);
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM pass_policy._refresh_role_state(v_oid);
    PERFORM pass_policy._audit('profile_assigned', v_role,
            jsonb_build_object('profile', 'default', 'unassigned', true));
    PERFORM pass_policy._shmem('reload');
END
$$;
COMMENT ON FUNCTION unassign_profile(name) IS 'Removes the profile assignment of a role (back to "default")';

/*
 * The generated password exists only in a local variable and in the result
 * of the call: it is never written to a table, the audit, a NOTIFY payload,
 * a RAISE or the server log (see _set_password()).
 * The ALTER ROLE fires the C hook, which checks the policy and calls
 * record_password_change(); _ensure_recorded() covers the case where the
 * hook did not run.
 */
CREATE FUNCTION rotate_password(role name, length int DEFAULT 24)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role    name := $1;
    v_oid     oid;
    v_profile text;
    v_pwd     text;
    v_vu      jsonb;
BEGIN
    PERFORM pass_policy._require_admin();
    v_oid := pass_policy._require_target_allowed(v_role);
    SELECT p.name INTO v_profile FROM pass_policy.effective_profile(v_role) p;

    v_pwd := pass_policy.generate_password(coalesce($2, 24), v_profile);
    IF v_pwd IS NULL THEN
        RAISE EXCEPTION 'pg_pass_policy: password generation failed';
    END IF;
    PERFORM pass_policy._set_password(v_role, v_pwd);
    PERFORM pass_policy._ensure_recorded(v_role);

    UPDATE pass_policy.role_state s SET must_change = false WHERE s.role_oid = v_oid;
    PERFORM pass_policy._refresh_role_state(v_oid);
    v_vu := pass_policy._apply_valid_until(v_oid,
              CASE WHEN pass_policy._guc_on('pg_pass_policy.manage_valid_until', true)
                   THEN 'force' ELSE 'unblock' END);

    PERFORM pass_policy._audit('password_rotated', v_role,
            jsonb_build_object('profile', v_profile, 'length', coalesce($2, 24),
                               'valid_until', (SELECT a.rolvaliduntil FROM pg_catalog.pg_authid a
                                                WHERE a.oid = v_oid)));
    RETURN v_pwd;
END
$$;
COMMENT ON FUNCTION rotate_password(name, int) IS 'Generates and sets a new password; returns it once (never stored or logged)';

CREATE FUNCTION expire_password(role name)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role name := $1;
    v_oid  oid;
    v_now  timestamptz := now();
BEGIN
    PERFORM pass_policy._require_admin();
    v_oid := pass_policy._require_target_allowed(v_role);
    PERFORM pass_policy._ensure_state(v_oid);
    UPDATE pass_policy.role_state s
       SET must_change = true, expires_at = v_now, grace_until = v_now,
           last_warned_at = v_now, valid_until_synced = v_now
     WHERE s.role_oid = v_oid;
    EXECUTE format('ALTER ROLE %I VALID UNTIL %L', v_role, v_now);
    PERFORM pass_policy._audit('password_expired', v_role,
            jsonb_build_object('manual', true, 'valid_until', v_now));
END
$$;
COMMENT ON FUNCTION expire_password(name) IS 'Forces the expiry of a role password now (must_change, VALID UNTIL now())';

CREATE FUNCTION lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role  name := $1;
    v_oid   oid;
    v_until timestamptz;
BEGIN
    PERFORM pass_policy._require_admin();
    v_oid := pass_policy._require_target_allowed(v_role);
    IF $2 IS NOT NULL AND $2 <= interval '0' THEN
        RAISE EXCEPTION 'pg_pass_policy: lock duration must be positive'
              USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_until := CASE WHEN $2 IS NULL THEN 'infinity'::timestamptz ELSE now() + $2 END;
    PERFORM pass_policy._ensure_state(v_oid);
    UPDATE pass_policy.role_state s
       SET locked_until = v_until, locked_by = 'manual', lock_reason = $3
     WHERE s.role_oid = v_oid;
    PERFORM pass_policy._shmem('lock', v_role::text, CASE WHEN $2 IS NULL THEN NULL ELSE v_until END);
    PERFORM pass_policy._audit('role_locked', v_role,
            jsonb_build_object('by', 'manual', 'until', v_until, 'reason', $3));
END
$$;
COMMENT ON FUNCTION lock_role(name, interval, text) IS 'Locks a role (NULL duration = until unlock_role)';

CREATE FUNCTION unlock_role(role name)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role name := $1;
    v_oid  oid;
BEGIN
    PERFORM pass_policy._require_admin();
    v_oid := pass_policy._require_target_allowed(v_role);
    UPDATE pass_policy.role_state s
       SET locked_until = NULL, locked_by = NULL, lock_reason = NULL
     WHERE s.role_oid = v_oid;
    PERFORM pass_policy._shmem('unlock', v_role::text);
    PERFORM pass_policy._shmem('reset', v_role::text);
    PERFORM pass_policy._audit('role_unlocked', v_role, jsonb_build_object('by', 'manual'));
END
$$;
COMMENT ON FUNCTION unlock_role(name) IS 'Unlocks a role and resets its failure counter';

CREATE FUNCTION purge_audit(older_than interval DEFAULT '365 days')
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    n bigint;
BEGIN
    PERFORM pass_policy._require_admin();
    DELETE FROM pass_policy.audit_log l WHERE l.event_time < now() - coalesce($1, '365 days');
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n > 0 THEN
        PERFORM pass_policy._audit('maintenance', NULL,
                jsonb_build_object('purged_audit_rows', n, 'older_than', $1));
    END IF;
    RETURN n;
END
$$;
COMMENT ON FUNCTION purge_audit(interval) IS 'Deletes audit rows older than an interval; returns the number deleted';

CREATE FUNCTION load_dictionary(words text[])
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    n int;
BEGIN
    PERFORM pass_policy._require_admin();
    INSERT INTO pass_policy.dictionary (word)
    SELECT DISTINCT lower(btrim(w)) FROM unnest($1) AS w
     WHERE w IS NOT NULL AND btrim(w) <> ''
    ON CONFLICT (word) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
COMMENT ON FUNCTION load_dictionary(text[]) IS 'Adds words to the password blocklist; returns the number of new words';

CREATE FUNCTION create_rotation_pair(pair text, role_a name, role_b name, group_role name)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_pair  text := $1;
    v_group name := $4;
    v_role  name;
BEGIN
    PERFORM pass_policy._require_admin();
    IF $2 = $3 OR $2 = $4 OR $3 = $4 THEN
        RAISE EXCEPTION 'pg_pass_policy: role_a, role_b and group_role must be distinct'
              USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = v_group) THEN
        RAISE EXCEPTION 'pg_pass_policy: group role "%" does not exist', v_group
              USING ERRCODE = 'undefined_object',
                    HINT = 'Create the group role holding the privileges first.';
    END IF;
    -- GRANT group_role TO role_a/role_b runs below as superuser (SECURITY
    -- DEFINER): a non-superuser admin must not obtain a LOGIN member of a
    -- superuser, of a pg_* role or of a member of one (SPEC §8.4).
    PERFORM pass_policy._require_target_allowed(v_group);
    IF EXISTS (SELECT FROM pass_policy.rotation_pair rp WHERE rp.pair_name = v_pair) THEN
        RAISE EXCEPTION 'pg_pass_policy: rotation pair "%" already exists', v_pair
              USING ERRCODE = 'duplicate_object';
    END IF;
    FOREACH v_role IN ARRAY ARRAY[$2, $3] LOOP
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = v_role) THEN
            EXECUTE format('CREATE ROLE %I LOGIN INHERIT', v_role);
        ELSE
            PERFORM pass_policy._require_target_allowed(v_role);
        END IF;
        IF NOT pg_catalog.pg_has_role(v_role, v_group, 'MEMBER') THEN
            EXECUTE format('GRANT %I TO %I', v_group, v_role);
        END IF;
    END LOOP;
    INSERT INTO pass_policy.rotation_pair (pair_name, role_a, role_b, group_role)
    VALUES (v_pair, $2, $3, v_group);
    PERFORM pass_policy._audit('profile_changed', NULL,
            jsonb_build_object('action', 'create_rotation_pair', 'pair', v_pair,
                               'role_a', $2, 'role_b', $3, 'group_role', v_group));
END
$$;
COMMENT ON FUNCTION create_rotation_pair(text, name, name, name) IS 'Declares a rotation pair, creating missing login roles as members of the group';

CREATE FUNCTION switch_rotation_pair(pair text, length int DEFAULT 24)
RETURNS TABLE (active_role text, password text, previous_role text, previous_valid_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    rp        pass_policy.rotation_pair;
    v_new     name;
    v_old     name;
    v_new_oid oid;
    v_old_oid oid;
    v_profile text;
    v_pwd     text;
    v_bound   timestamptz;
BEGIN
    PERFORM pass_policy._require_admin();
    SELECT * INTO rp FROM pass_policy.rotation_pair r WHERE r.pair_name = $1 FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: rotation pair "%" does not exist', $1
              USING ERRCODE = 'undefined_object';
    END IF;
    v_old := rp.active_role;
    v_new := CASE WHEN rp.active_role = rp.role_a THEN rp.role_b ELSE rp.role_a END;
    v_new_oid := pass_policy._require_target_allowed(v_new);
    IF v_old IS NOT NULL THEN
        v_old_oid := pass_policy._require_target_allowed(v_old);
    END IF;

    SELECT p.name INTO v_profile FROM pass_policy.effective_profile(v_new) p;
    v_pwd := pass_policy.generate_password(coalesce($2, 24), v_profile);
    IF v_pwd IS NULL THEN
        RAISE EXCEPTION 'pg_pass_policy: password generation failed';
    END IF;

    -- the new active role must not stay bounded by a previous switch
    UPDATE pass_policy.rotation_pair r
       SET active_role = v_new, previous_role = v_old, switched_at = now(),
           previous_valid_until = NULL
     WHERE r.pair_name = rp.pair_name;

    PERFORM pass_policy._set_password(v_new, v_pwd);
    PERFORM pass_policy._ensure_recorded(v_new);
    UPDATE pass_policy.role_state s SET must_change = false WHERE s.role_oid = v_new_oid;
    PERFORM pass_policy._refresh_role_state(v_new_oid);
    PERFORM pass_policy._apply_valid_until(v_new_oid, 'force');

    IF v_old IS NOT NULL THEN
        SELECT now() + p.grace_period INTO v_bound FROM pass_policy.effective_profile(v_old) p;
        UPDATE pass_policy.rotation_pair r SET previous_valid_until = v_bound
         WHERE r.pair_name = rp.pair_name;
        PERFORM pass_policy._ensure_state(v_old_oid);
        -- The bound is recorded in role_state too (as expire_password() does),
        -- not only derived from rotation_pair: should the pair row disappear
        -- (group role dropped, manual DELETE), the old password must not
        -- become valid again at the next VALID UNTIL synchronisation.
        -- last_warned_at = now() avoids an immediate expiry_warning.
        UPDATE pass_policy.role_state s
           SET must_change = true, expires_at = v_bound, grace_until = v_bound,
               last_warned_at = now(), valid_until_synced = v_bound
         WHERE s.role_oid = v_old_oid;
        PERFORM pass_policy._apply_valid_until(v_old_oid, 'force');
    END IF;

    PERFORM pass_policy._audit('pair_switched', v_new,
            jsonb_build_object('pair', rp.pair_name, 'active_role', v_new,
                               'previous_role', v_old, 'previous_valid_until', v_bound));

    active_role := v_new;
    password := v_pwd;
    previous_role := v_old;
    previous_valid_until := v_bound;
    RETURN NEXT;
END
$$;
COMMENT ON FUNCTION switch_rotation_pair(text, int) IS 'Rotates a pair: new password for the inactive role, bounds the old one; returns the password once';

/*
 * run_maintenance(): one pass of what the background worker does; may also
 * be scheduled with pg_cron (runs fine without the worker / shmem).
 *  a0. re-map role_oid by role name (restore on another cluster, CREATE ROLE)
 *      and follow role renames ;
 *  a.  purge rows of roles that no longer exist ;
 *  b.  reconcile pg_authid.rolpassword with the history ;
 *  c.  recompute expires_at / grace_until ;
 *  d.  VALID UNTIL synchronisation (pass_policy.manage_valid_until); when
 *      it is off, only lifts a VALID UNTIL in the past that the extension
 *      wrote itself (expire_password, former sync) once the password has
 *      been changed ('unblock') ;
 *  e.  expiry_warning (max once a day) / password_expired (once) ;
 *  f.  automatic unlock of expired locks ;
 *  g.  'maintenance' audit row only if something was done ;
 *  h.  shmem_reload() is ALWAYS called: the worker decides whether anything
 *      changed (simpler and cheap; no extra bookkeeping in SQL).
 */
CREATE FUNCTION run_maintenance()
RETURNS TABLE (action text, role_name text, details jsonb)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    r          record;
    v_manage   bool := pass_policy._guc_on('pg_pass_policy.manage_valid_until', true);
    v_res      jsonb;
    v_n        int;
    v_summary  jsonb := '{}';
    v_actions  int := 0;
BEGIN
    PERFORM pass_policy._require_admin();
    -- step b updates password_history.verifier with pg_authid.rolpassword:
    -- keep auto_explain from logging those values (see _set_password)
    IF current_setting('auto_explain.log_min_duration', true) IS NOT NULL THEN
        PERFORM set_config('auto_explain.log_min_duration', '-1', true);
    END IF;

    ---------------------------------------------------------------- a0
    -- name wins: rows whose role_name exists with another OID get that OID
    FOR r IN
        SELECT 'role_state' AS tbl, s.role_oid AS old_oid, a.oid AS new_oid, s.role_name AS rname
          FROM pass_policy.role_state s JOIN pg_catalog.pg_authid a ON a.rolname = s.role_name
         WHERE a.oid <> s.role_oid
        UNION ALL
        SELECT 'role_profile', p.role_oid, a.oid, p.role_name
          FROM pass_policy.role_profile p JOIN pg_catalog.pg_authid a ON a.rolname = p.role_name
         WHERE a.oid <> p.role_oid
    LOOP
        IF r.tbl = 'role_state' THEN
            IF EXISTS (SELECT FROM pass_policy.role_state x WHERE x.role_oid = r.new_oid) THEN
                DELETE FROM pass_policy.role_state x WHERE x.role_oid = r.old_oid;
            ELSE
                UPDATE pass_policy.role_state x SET role_oid = r.new_oid WHERE x.role_oid = r.old_oid;
            END IF;
        ELSE
            IF EXISTS (SELECT FROM pass_policy.role_profile x WHERE x.role_oid = r.new_oid) THEN
                DELETE FROM pass_policy.role_profile x WHERE x.role_oid = r.old_oid;
            ELSE
                UPDATE pass_policy.role_profile x SET role_oid = r.new_oid WHERE x.role_oid = r.old_oid;
            END IF;
        END IF;
        action := 'remap'; role_name := r.rname;
        details := jsonb_build_object('table', r.tbl, 'old_oid', r.old_oid, 'new_oid', r.new_oid);
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;
    UPDATE pass_policy.password_history h SET role_oid = a.oid
      FROM pg_catalog.pg_authid a
     WHERE a.rolname = h.role_name AND h.role_oid IS DISTINCT FROM a.oid;
    -- renames: OID still exists, old name gone
    UPDATE pass_policy.role_state s SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = s.role_oid AND a.rolname <> s.role_name
       AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid b WHERE b.rolname = s.role_name);
    UPDATE pass_policy.role_profile p SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = p.role_oid AND a.rolname <> p.role_name
       AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid b WHERE b.rolname = p.role_name);
    UPDATE pass_policy.password_history h SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = h.role_oid AND a.rolname <> h.role_name
       AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid b WHERE b.rolname = h.role_name);

    ---------------------------------------------------------------- a
    FOR r IN
        DELETE FROM pass_policy.role_state s
         WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.oid = s.role_oid)
        RETURNING s.role_name AS rname
    LOOP
        action := 'purge'; role_name := r.rname; details := '{"table":"role_state"}';
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;
    FOR r IN
        DELETE FROM pass_policy.role_profile p
         WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.oid = p.role_oid)
        RETURNING p.role_name AS rname
    LOOP
        action := 'purge'; role_name := r.rname; details := '{"table":"role_profile"}';
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;
    DELETE FROM pass_policy.password_history h
     WHERE h.role_oid IS NULL
        OR NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.oid = h.role_oid);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        v_summary := v_summary || jsonb_build_object('purged_history_rows', v_n);
    END IF;
    FOR r IN
        DELETE FROM pass_policy.rotation_pair rp
         WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = rp.role_a)
            OR NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = rp.role_b)
            OR NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = rp.group_role)
        RETURNING rp.pair_name AS pname, rp.previous_role AS prev_role,
                  rp.previous_valid_until AS prev_until,
                  (SELECT a.oid FROM pg_catalog.pg_authid a WHERE a.rolname = rp.previous_role) AS prev_oid
    LOOP
        -- the bound of the previous role must survive the pair row (pairs
        -- switched before role_state carried it)
        IF r.prev_oid IS NOT NULL AND r.prev_until IS NOT NULL THEN
            PERFORM pass_policy._ensure_state(r.prev_oid);
            UPDATE pass_policy.role_state s
               SET must_change = true, expires_at = r.prev_until, grace_until = r.prev_until,
                   last_warned_at = coalesce(s.last_warned_at, now())
             WHERE s.role_oid = r.prev_oid
               AND (NOT s.must_change OR s.grace_until IS NULL OR s.grace_until > r.prev_until);
        END IF;
        action := 'purge'; role_name := NULL;
        details := jsonb_build_object('table', 'rotation_pair', 'pair', r.pname);
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;

    ---------------------------------------------------------------- b
    FOR r IN
        SELECT a.oid, a.rolname::text AS rname, a.rolpassword,
               s.role_oid IS NOT NULL AS has_state, s.password_changed_at, s.verifier_pending,
               h.id AS hid, h.verifier AS hverifier, h.changed_at AS hchanged
          FROM pg_catalog.pg_authid a
          LEFT JOIN pass_policy.role_state s ON s.role_oid = a.oid
          LEFT JOIN LATERAL (SELECT h1.id, h1.verifier, h1.changed_at
                               FROM pass_policy.password_history h1
                              WHERE h1.role_oid = a.oid
                              ORDER BY h1.changed_at DESC, h1.id DESC LIMIT 1) h ON true
         WHERE a.rolcanlogin AND a.rolpassword IS NOT NULL
           AND (h.id IS NULL OR h.verifier <> a.rolpassword OR s.role_oid IS NULL
                OR s.verifier_pending OR s.password_changed_at IS NULL)
    LOOP
        IF r.hid IS NULL THEN
            -- no history at all (role older than the extension, or changed
            -- while the hook was not active)
            INSERT INTO pass_policy.password_history (role_oid, role_name, verifier, changed_at)
            VALUES (r.oid, r.rname, r.rolpassword, coalesce(r.password_changed_at, now()));
            INSERT INTO pass_policy.role_state AS s (role_oid, role_name, password_changed_at)
            VALUES (r.oid, r.rname, now())
            ON CONFLICT (role_oid) DO UPDATE
               SET password_changed_at = coalesce(s.password_changed_at, now()),
                   verifier_pending = false;
            action := 'reconcile'; role_name := r.rname;
            details := jsonb_build_object('reason', 'no_history',
                                          'changed_at', coalesce(r.password_changed_at, now()));
        ELSIF r.hverifier <> r.rolpassword AND (NOT r.has_state OR r.verifier_pending) THEN
            -- expected mismatch: the hook recorded its own verifier (other salt)
            UPDATE pass_policy.password_history h SET verifier = r.rolpassword WHERE h.id = r.hid;
            INSERT INTO pass_policy.role_state AS s (role_oid, role_name, password_changed_at)
            VALUES (r.oid, r.rname, r.hchanged)
            ON CONFLICT (role_oid) DO UPDATE SET verifier_pending = false;
            CONTINUE;                       -- bookkeeping only, not reported
        ELSIF r.hverifier <> r.rolpassword THEN
            -- the password was changed without going through the hook
            INSERT INTO pass_policy.password_history (role_oid, role_name, verifier, changed_at)
            VALUES (r.oid, r.rname, r.rolpassword, now());
            DELETE FROM pass_policy.password_history h
             WHERE h.role_oid = r.oid
               AND h.id NOT IN (SELECT h2.id FROM pass_policy.password_history h2
                                 WHERE h2.role_oid = r.oid
                                 ORDER BY h2.changed_at DESC, h2.id DESC
                                 LIMIT (SELECT greatest(e.history_count, 1)
                                          FROM pass_policy._role_effective_profile e
                                         WHERE e.role_oid = r.oid));
            UPDATE pass_policy.role_state s
               SET password_changed_at = now(), last_warned_at = NULL,
                   must_change = false, verifier_pending = false
             WHERE s.role_oid = r.oid;
            PERFORM pass_policy._audit('password_changed', r.rname,
                    jsonb_build_object('source', 'reconciliation'));
            action := 'reconcile'; role_name := r.rname;
            details := jsonb_build_object('reason', 'changed_outside_hook');
        ELSE
            -- verifier matches: create a missing state row / clear the flag
            INSERT INTO pass_policy.role_state AS s (role_oid, role_name, password_changed_at)
            VALUES (r.oid, r.rname, r.hchanged)
            ON CONFLICT (role_oid) DO UPDATE
               SET verifier_pending = false,
                   password_changed_at = coalesce(s.password_changed_at, EXCLUDED.password_changed_at);
            CONTINUE;
        END IF;
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;

    ---------------------------------------------------------------- c
    v_n := pass_policy._refresh_role_state(NULL);
    IF v_n > 0 THEN
        v_summary := v_summary || jsonb_build_object('expiry_recomputed', v_n);
    END IF;

    ---------------------------------------------------------------- d
    -- manage_valid_until = off: only roles whose current VALID UNTIL was
    -- written by the extension (= valid_until_synced) and whose password has
    -- been changed since (must_change cleared) are considered, in 'unblock'
    -- mode (rewrites only a VALID UNTIL already in the past).
    FOR r IN
        SELECT s.role_oid, s.role_name AS rname
          FROM pass_policy.role_state s
          JOIN pg_catalog.pg_authid a ON a.oid = s.role_oid
         WHERE a.rolcanlogin AND NOT pass_policy._is_exempt(a.rolname)
           AND (v_manage
                OR (NOT s.must_change AND a.rolvaliduntil IS NOT DISTINCT FROM s.valid_until_synced))
    LOOP
        v_res := pass_policy._apply_valid_until(r.role_oid, CASE WHEN v_manage THEN 'sync' ELSE 'unblock' END);
        IF v_res IS NOT NULL THEN
            PERFORM pass_policy._audit('valid_until_synced', r.rname, v_res);
            action := 'valid_until_synced'; role_name := r.rname; details := v_res;
            v_actions := v_actions + 1;
            RETURN NEXT;
        END IF;
    END LOOP;

    ---------------------------------------------------------------- e
    FOR r IN
        SELECT s.role_oid, s.role_name AS rname, s.expires_at, s.grace_until, s.last_warned_at,
               e.warn_before
          FROM pass_policy.role_state s
          JOIN pass_policy._role_effective_profile e ON e.role_oid = s.role_oid
          JOIN pg_catalog.pg_authid a ON a.oid = s.role_oid
         WHERE s.expires_at IS NOT NULL AND a.rolcanlogin
           AND NOT pass_policy._is_exempt(a.rolname)
    LOOP
        IF now() >= r.expires_at THEN
            IF r.last_warned_at IS NULL OR r.last_warned_at < r.expires_at THEN
                UPDATE pass_policy.role_state s SET last_warned_at = now() WHERE s.role_oid = r.role_oid;
                details := jsonb_build_object('expires_at', r.expires_at, 'grace_until', r.grace_until);
                PERFORM pass_policy._audit('password_expired', r.rname, details);
                action := 'password_expired'; role_name := r.rname;
                v_actions := v_actions + 1;
                RETURN NEXT;
            END IF;
        ELSIF r.expires_at - now() < r.warn_before THEN
            IF r.last_warned_at IS NULL OR r.last_warned_at < now() - interval '1 day' THEN
                UPDATE pass_policy.role_state s SET last_warned_at = now() WHERE s.role_oid = r.role_oid;
                details := jsonb_build_object('expires_at', r.expires_at,
                                              'days_left', floor(extract(epoch FROM r.expires_at - now()) / 86400));
                PERFORM pass_policy._audit('expiry_warning', r.rname, details);
                action := 'expiry_warning'; role_name := r.rname;
                v_actions := v_actions + 1;
                RETURN NEXT;
            END IF;
        END IF;
    END LOOP;

    ---------------------------------------------------------------- f
    FOR r IN
        UPDATE pass_policy.role_state s
           SET locked_until = NULL, locked_by = NULL, lock_reason = NULL
         WHERE s.locked_until < now()
        RETURNING s.role_name AS rname
    LOOP
        PERFORM pass_policy._shmem('unlock', r.rname);
        PERFORM pass_policy._audit('role_unlocked', r.rname, '{"by":"auto"}');
        action := 'role_unlocked'; role_name := r.rname; details := '{"by":"auto"}';
        v_actions := v_actions + 1;
        RETURN NEXT;
    END LOOP;

    ---------------------------------------------------------------- g
    IF v_actions > 0 OR v_summary <> '{}' THEN
        PERFORM pass_policy._audit('maintenance', NULL,
                v_summary || jsonb_build_object('actions', v_actions));
    END IF;

    ---------------------------------------------------------------- h
    PERFORM pass_policy._shmem('reload');
    RETURN;
END
$$;
COMMENT ON FUNCTION run_maintenance() IS 'One maintenance pass (worker or pg_cron): reconciliation, expiry, VALID UNTIL, alerts, unlocks';

-------------------------------------------------------------------------------
-- 7. Views (SPEC §4)
-------------------------------------------------------------------------------
CREATE VIEW v_role_status AS
SELECT q.role_name, q.profile, q.password_changed_at, q.expires_at, q.grace_until,
       CASE WHEN q.expires_at IS NULL THEN NULL
            ELSE floor(extract(epoch FROM q.expires_at - now()) / 86400)::int END AS days_left,
       q.locked_until, q.failed_count,
       CASE
           WHEN q.locked_until > now()                         THEN 'locked'
           WHEN q.must_change AND now() < q.grace_until        THEN 'grace'   -- previous role of a pair, still usable until its bound
           WHEN q.must_change                                  THEN 'expired'
           WHEN q.max_age IS NULL                              THEN 'never_expires'
           WHEN q.password_changed_at IS NULL                  THEN 'unknown'
           WHEN now() >= q.grace_until                         THEN 'expired'
           WHEN now() >= q.expires_at                          THEN 'grace'
           WHEN q.expires_at - now() < q.warn_before           THEN 'warning'
           ELSE 'ok'
       END AS status
  FROM (SELECT r.rolname::text AS role_name, e.name AS profile, e.max_age, e.warn_before,
               s.password_changed_at, coalesce(s.must_change, false) AS must_change,
               CASE WHEN s.must_change THEN s.expires_at
                    ELSE s.password_changed_at + e.max_age END AS expires_at,
               CASE WHEN s.must_change THEN s.grace_until
                    ELSE s.password_changed_at + e.max_age + e.grace_period END AS grace_until,
               nullif(greatest(s.locked_until, f.locked_until), '-infinity') AS locked_until,
               coalesce(f.failed_count, 0) AS failed_count
          FROM pg_catalog.pg_roles r
          JOIN _role_effective_profile e ON e.role_oid = r.oid
          LEFT JOIN role_state s ON s.role_oid = r.oid
          LEFT JOIN failed_attempts() f ON f.role_name = r.rolname
         WHERE r.rolcanlogin) q;
COMMENT ON VIEW v_role_status IS 'Password and lock status of every login role';

CREATE VIEW v_expiring AS
SELECT * FROM v_role_status WHERE status IN ('warning', 'grace', 'expired');
COMMENT ON VIEW v_expiring IS 'Login roles whose password is about to expire, in grace period or expired';

CREATE VIEW v_locked AS
SELECT v.role_name, v.locked_until, s.locked_by, s.lock_reason, v.failed_count
  FROM v_role_status v
  LEFT JOIN role_state s ON s.role_name = v.role_name
 WHERE v.status = 'locked';
COMMENT ON VIEW v_locked IS 'Currently locked roles';

CREATE VIEW v_recent_audit AS
SELECT l.id, l.event_time, l.event_type, l.role_name, l.actor, l.database,
       l.client_addr, l.application_name, l.details
  FROM audit_log l
 ORDER BY l.id DESC
 LIMIT 1000;
COMMENT ON VIEW v_recent_audit IS 'Last 1000 audit events';

-------------------------------------------------------------------------------
-- 8. Privileges
-------------------------------------------------------------------------------
/*
 * - schema USAGE to PUBLIC: the C hook calls effective_profile() and
 *   record_password_change() in the session of any user changing a
 *   password; every table stays REVOKEd from PUBLIC ;
 * - viewer: SELECT on tables and views, except password_history.verifier
 *   (column grant: the hashes are offline-cracking material) ;
 * - admin: member of viewer + EXECUTE on the administration API ;
 * - shmem_* and internal _* functions: no grant (called by SECURITY DEFINER
 *   code only).
 */
REVOKE ALL ON SCHEMA pass_policy FROM PUBLIC;
GRANT USAGE ON SCHEMA pass_policy TO PUBLIC, pass_policy_viewer, pass_policy_admin;

REVOKE ALL ON ALL TABLES IN SCHEMA pass_policy FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pass_policy FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA pass_policy FROM PUBLIC;

GRANT SELECT ON profile, role_profile, role_state, dictionary, audit_log, rotation_pair,
                v_role_status, v_expiring, v_locked, v_recent_audit
   TO pass_policy_viewer, pass_policy_admin;
GRANT SELECT (id, role_oid, role_name, changed_at) ON password_history
   TO pass_policy_viewer, pass_policy_admin;

-- called from any session by the C password hook
GRANT EXECUTE ON FUNCTION effective_profile(name), record_password_change(text, text),
                          audit(text, text, jsonb)
   TO PUBLIC;

-- needed by the views
GRANT EXECUTE ON FUNCTION failed_attempts(), worker_status()
   TO pass_policy_viewer, pass_policy_admin;

GRANT EXECUTE ON FUNCTION
    check_password(text, text),
    generate_password(int, text),
    create_profile(text, jsonb),
    alter_profile(text, jsonb),
    drop_profile(text),
    assign_profile(name, text),
    unassign_profile(name),
    rotate_password(name, int),
    expire_password(name),
    lock_role(name, interval, text),
    unlock_role(name),
    run_maintenance(),
    create_rotation_pair(text, name, name, name),
    switch_rotation_pair(text, int),
    purge_audit(interval),
    load_dictionary(text[])
   TO pass_policy_admin;
