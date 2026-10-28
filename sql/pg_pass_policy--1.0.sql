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
/*
 * Bounds of the generator, used by the CHECK constraints of profile and by
 * _rotate_role().  Both are SQL-standard bodies (parsed once, at CREATE
 * EXTENSION: the caller's search_path plays no part) and IMMUTABLE.
 *
 * _max_generated_length(): PPP_GEN_MAX_LENGTH (policy.c), the longest
 * password that generate_password() produces; the only copy of the value
 * on the SQL side (a profile whose bounds exceed it could never be
 * rotated).  Keep both values in step.
 */
CREATE FUNCTION _max_generated_length()
RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE
RETURN 512;
COMMENT ON FUNCTION _max_generated_length() IS 'Internal: longest password generate_password() produces (PPP_GEN_MAX_LENGTH)';

/*
 * _generator_minimum(): the shortest password generate_password() can build
 * for these class minima, the same computation as policy.c: at least one
 * lower-case letter, one upper-case letter and one digit are always drawn
 * (Max(min_x, 1)), min_special specials, and one special when the three
 * other classes do not reach min_classes on their own.  Computed in bigint
 * and capped to int4 so that four large minima are refused by the CHECK
 * (23514) instead of overflowing (22003).
 */
CREATE FUNCTION _generator_minimum(p_min_lower int, p_min_upper int, p_min_digit int,
                                   p_min_special int, p_min_classes int)
RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE
RETURN least(
           greatest(p_min_lower, 1)::bigint
           + greatest(p_min_upper, 1)
           + greatest(p_min_digit, 1)
           + CASE WHEN 3 + (p_min_special > 0)::int < p_min_classes THEN 1
                  ELSE greatest(p_min_special, 0) END,
           2147483647)::int;
COMMENT ON FUNCTION _generator_minimum(int, int, int, int, int) IS 'Internal: shortest password generate_password() can build for these class minima (min_lower, min_upper, min_digit, min_special, min_classes)';

CREATE TABLE profile (
    profile_id        serial PRIMARY KEY,
    name              text NOT NULL UNIQUE
                      CHECK (name ~ '^[A-Za-z0-9_.-]{1,63}$'),
    -- upper bound: max_length <= _max_generated_length() and
    -- profile_length_range (min_length <= max_length)
    min_length        int NOT NULL DEFAULT 12  CHECK (min_length >= 8),
    max_length        int NOT NULL DEFAULT 128 CHECK (max_length <= pass_policy._max_generated_length()),
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
    -- 0 = no window (SPEC §11).  Durations are handed to the shared memory in
    -- whole seconds (worker.c): a non-zero window or a lock shorter than one
    -- second would be rounded to 0 (no window / lock already expired).
    failure_window    interval NOT NULL DEFAULT '15 minutes'
                      CHECK (failure_window = interval '0' OR failure_window >= interval '1 second'),
    lock_duration     interval     DEFAULT '30 minutes' CHECK (lock_duration >= interval '1 second'),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT profile_length_range CHECK (max_length >= min_length),
    -- what generate_password() really needs, not the plain sum of the minima
    CONSTRAINT profile_classes_fit  CHECK (pass_policy._generator_minimum(min_lower, min_upper, min_digit,
                                                                          min_special, min_classes) <= max_length)
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
/*
 * word_sha256 = SHA-256 of the raw bytes of word (server encoding).  The C
 * hook looks a candidate password up by the digest of its lower-cased form
 * only: the clear text never reaches SQL and no word is read back.  The
 * bytes are taken with decode(..., 'escape') (IMMUTABLE, no encoding
 * conversion; backslashes doubled first) rather than convert_to(), which is
 * only STABLE and cannot be used in a generated column, or textsend(), which
 * converts to the client encoding.  The backslash is written chr(92): a
 * '\' literal would mean one or two characters depending on
 * standard_conforming_strings, and CREATE EXTENSION fails when it is off.
 */
CREATE TABLE dictionary (
    word        text PRIMARY KEY CHECK (word = lower(word) AND word <> ''),
    word_sha256 bytea NOT NULL
                GENERATED ALWAYS AS (sha256(decode(replace(word, chr(92), chr(92) || chr(92)), 'escape'))) STORED
);
CREATE UNIQUE INDEX dictionary_sha256_idx ON dictionary (word_sha256);
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

-- expired_only: lift the lock only if it has expired at COMMIT (step f of
-- run_maintenance(): never lift a newer automatic lock not yet in role_state)
-- Returns false (nothing queued) when expired_only and an active lock is held.
CREATE FUNCTION shmem_unlock_role(role text, expired_only boolean DEFAULT false)
RETURNS bool
AS 'MODULE_PATHNAME', 'ppp_shmem_unlock_role'
LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION shmem_unlock_role(text, boolean) IS 'Removes the shared-memory lock of a role (expired_only: only if it has expired; false if an active lock is kept)';

CREATE FUNCTION shmem_reset_failures(role text)
RETURNS void
AS 'MODULE_PATHNAME', 'ppp_shmem_reset_failures'
LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION shmem_reset_failures(text) IS 'Resets the shared-memory failure counter of a role';

CREATE FUNCTION worker_status()
RETURNS TABLE (pid int, last_run timestamptz, last_reload timestamptz, tracked_roles int,
               locks_loaded bool)
AS 'MODULE_PATHNAME', 'ppp_worker_status'
LANGUAGE C VOLATILE PARALLEL SAFE;
COMMENT ON FUNCTION worker_status() IS 'State of the pg_pass_policy background worker (locks_loaded: false while the start-up window refuses connections)';

/*
 * Addition to SPEC §4: true only while this backend is executing the
 * pg_pass_policy check_password_hook (static flag set by the C hook around
 * its SPI calls).  Defence in depth for record_password_change(): it is
 * not granted to PUBLIC any more (the hook calls it as superuser), but
 * should EXECUTE be granted by mistake, a user could
 * otherwise call record_password_change() on himself and push back his own
 * expiry without changing his password.
 */
CREATE FUNCTION _in_password_hook()
RETURNS bool
AS 'MODULE_PATHNAME', 'ppp_in_password_hook'
LANGUAGE C VOLATILE PARALLEL RESTRICTED;
COMMENT ON FUNCTION _in_password_hook() IS 'Internal: true while the pg_pass_policy password hook is running in this backend';

/*
 * Addition to SPEC §4: PID of the background worker (NULL when it is not
 * running), read atomically from shared memory.  Used by _audit()
 * for every row, instead of worker_status() (tuplestore, hash size).
 */
/*
 * Addition to SPEC §4: true if the password hook recorded a password change
 * of this role in the current transaction (backend-local flag cleared at
 * COMMIT / ABORT and when its sub-transaction is rolled back).  Used by
 * _ensure_recorded() after an ALTER ROLE issued by the extension itself.
 */
CREATE FUNCTION _record_done(role name)
RETURNS bool
AS 'MODULE_PATHNAME', 'ppp_record_done'
LANGUAGE C STRICT VOLATILE PARALLEL RESTRICTED;
COMMENT ON FUNCTION _record_done(name) IS 'Internal: true if the pg_pass_policy password hook recorded a change of this role in the current transaction';

CREATE FUNCTION _worker_pid()
RETURNS int
AS 'MODULE_PATHNAME', 'ppp_worker_pid'
LANGUAGE C VOLATILE PARALLEL SAFE;
COMMENT ON FUNCTION _worker_pid() IS 'Internal: PID of the pg_pass_policy background worker, NULL if not running';

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
        -- pg_has_role() by name raises "role does not exist" once
        -- pass_policy_admin has been dropped: look the role up first and
        -- pass its OID (a superuser keeps access through rolsuper)
        OR EXISTS (SELECT FROM pg_catalog.pg_roles g
                    WHERE g.rolname = 'pass_policy_admin'
                      AND pg_catalog.pg_has_role(session_user, g.oid, 'MEMBER'))
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
 * privileged in itself (_is_privileged) when it has SUPERUSER, REPLICATION
 * or BYPASSRLS, when it is a predefined pg_* role (pg_execute_server_program
 * runs OS commands, pg_write_server_files writes any server file...;
 * pg_database_owner is excluded: every database owner is an implicit member
 * and it carries no privilege beyond the ownership already held), or, on
 * PostgreSQL <= 15, when it has CREATEROLE (which could then grant pg_*
 * roles and change the password of any non-superuser).  A target is refused
 * when it is privileged itself or a member, even indirectly, of a
 * privileged role (SET ROLE / INHERIT give its privileges): the same
 * predicate is applied to the target and to every role it belongs to.
 */
CREATE FUNCTION _is_privileged(p_oid oid)
RETURNS bool
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT coalesce((SELECT a.rolsuper OR a.rolreplication OR a.rolbypassrls
                            OR (starts_with(a.rolname, 'pg_') AND a.rolname <> 'pg_database_owner')
                            OR (a.rolcreaterole AND current_setting('server_version_num')::int < 160000)
                       -- pg_roles, not pg_authid: readable by the viewer/admin
                       -- roles the function is granted to
                       FROM pg_catalog.pg_roles a WHERE a.oid = p_oid), false)
$$;
COMMENT ON FUNCTION _is_privileged(oid) IS 'Internal: true if a role is privileged in itself (SUPERUSER, REPLICATION, BYPASSRLS, pg_*, CREATEROLE on PG <= 15)';

CREATE FUNCTION _require_target_allowed(p_role name)
RETURNS oid
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    r record;
BEGIN
    SELECT a.oid, a.rolname INTO r
      FROM pg_catalog.pg_authid a WHERE a.rolname = p_role;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_pass_policy: role "%" does not exist', p_role
              USING ERRCODE = 'undefined_object';
    END IF;
    IF coalesce((SELECT x.rolsuper FROM pg_catalog.pg_roles x WHERE x.rolname = session_user), false) THEN
        RETURN r.oid;
    END IF;
    -- The target and its ancestors only, walked up pg_auth_members: the
    -- same set as pg_has_role(target, x, 'MEMBER') (is_member_of_role():
    -- every grant, whatever its INHERIT / SET options, any depth), with the
    -- implicit membership of the owner of the current database in
    -- pg_database_owner that roles_is_member_of() adds.  pg_database_owner
    -- is not privileged itself, and since PG 16 it cannot be a member of any
    -- role (no ancestor); the branch is kept so that the walk stays exactly
    -- that of pg_has_role() whatever the version.  A superuser target is
    -- privileged in itself.  UNION stops on cycles.
    IF EXISTS (WITH RECURSIVE anc(oid) AS (
                   SELECT r.oid
                   UNION
                   SELECT up.roleid
                     FROM anc
                    CROSS JOIN LATERAL (
                          SELECT m.roleid FROM pg_catalog.pg_auth_members m
                           WHERE m.member = anc.oid
                          UNION ALL
                          SELECT 'pg_database_owner'::pg_catalog.regrole::pg_catalog.oid
                           WHERE anc.oid = (SELECT d.datdba FROM pg_catalog.pg_database d
                                             WHERE d.datname = pg_catalog.current_database())
                          ) up(roleid))
               SELECT FROM anc WHERE pass_policy._is_privileged(anc.oid)) THEN
        RAISE EXCEPTION 'pg_pass_policy: only a superuser can manage privileged role "%"', p_role
              USING ERRCODE = 'insufficient_privilege',
                    DETAIL = 'The role has, or is a member of a role having, SUPERUSER, REPLICATION, BYPASSRLS, predefined (pg_*) or, on PostgreSQL 15 and older, CREATEROLE privileges.';
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

/*
 * Addition to SPEC §4: SQL access to ppp_role_is_exempt() (C), so that the
 * SQL side and the C hooks share a single parsing of
 * pg_pass_policy.exempt_roles (SplitIdentifierString() rules, list split
 * once by the GUC assign hook).  STABLE: the GUC is SIGHUP and only changes
 * between statements.
 */
CREATE FUNCTION _is_exempt(p_role text)
RETURNS bool
AS 'MODULE_PATHNAME', 'ppp_is_exempt'
LANGUAGE C STABLE STRICT;
COMMENT ON FUNCTION _is_exempt(text) IS 'Internal: true if the role is listed in pg_pass_policy.exempt_roles (same function as the C hooks)';

/*
 * Calls to the C shared-memory functions.  'lock', 'unlock' and
 * 'unlock_expired' (unlock only if the lock has expired, see
 * shmem_unlock_role) let their errors through: role_state (and the audit row) must never claim a lock or
 * an unlock that the shared memory did not receive, e.g. when the library is
 * not preloaded (fail-closed: lock_role() and unlock_role() fail and their
 * transaction is rolled back).  'reload' and 'reset' only optimise or tidy
 * up (the worker reloads at its next cycle anyway, a stale counter expires
 * with its window): their failures are downgraded to WARNINGs so that they
 * never break maintenance or administration.
 */
CREATE FUNCTION _shmem(p_op text, p_role text DEFAULT NULL, p_until timestamptz DEFAULT NULL)
RETURNS bool
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    CASE p_op
        WHEN 'lock'   THEN PERFORM pass_policy.shmem_lock_role(p_role, p_until);
                           RETURN true;
        WHEN 'unlock' THEN PERFORM pass_policy.shmem_unlock_role(p_role);
                           RETURN true;
        -- false: an active (newer) lock is held, nothing is lifted
        WHEN 'unlock_expired' THEN RETURN pass_policy.shmem_unlock_role(p_role, true);
        ELSE NULL;
    END CASE;
    BEGIN
        CASE p_op
            WHEN 'reload' THEN PERFORM pass_policy.shmem_reload();
            WHEN 'reset'  THEN PERFORM pass_policy.shmem_reset_failures(p_role);
        END CASE;
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'pg_pass_policy: shared memory call "%" failed: %', p_op, SQLERRM;
        RETURN false;
    END;
    RETURN true;
END
$$;
COMMENT ON FUNCTION _shmem(text, text, timestamptz) IS 'Internal: calls a shmem_* C function; lock/unlock errors are raised, reload/reset errors become warnings';

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
    -- (_worker_pid() is NULL when the worker is not running)
    IF pass_policy._worker_pid() IS NOT DISTINCT FROM pg_catalog.pg_backend_pid() THEN
        v_actor := 'worker';
    END IF;

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
 *   'unblock' manage_valid_until = off, or exempt role: writes only if the
 *             current VALID UNTIL is already in the past, and then
 *             'infinity' (bounded by a rotation pair only): the extension
 *             does not manage the expiry, it only lifts a block it caused.
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
        -- not grace_until: with manage_valid_until = off nothing would ever
        -- lift that new value once passed, and the role would end up blocked
        v_new := coalesce(r.pair_bound, 'infinity');
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

-- Keeps the history_count most recent history rows of a role (at least
-- one: the reference for the reconciliation of run_maintenance()).
CREATE FUNCTION _trim_history(p_oid oid)
RETURNS void
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    DELETE FROM pass_policy.password_history h
     WHERE h.role_oid = p_oid
       AND h.id NOT IN (SELECT h2.id FROM pass_policy.password_history h2
                         WHERE h2.role_oid = p_oid
                         ORDER BY h2.changed_at DESC, h2.id DESC
                         LIMIT (SELECT greatest(e.history_count, 1)
                                  FROM pass_policy._role_effective_profile e
                                 WHERE e.role_oid = p_oid))
$$;
COMMENT ON FUNCTION _trim_history(oid) IS 'Internal: truncates the password history of a role to history_count rows';

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

    PERFORM pass_policy._trim_history(v_oid);

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
    v_ver text;
BEGIN
    -- explicit flag set by the C hook (no guess from role_state)
    IF NOT pass_policy._record_done(p_role) THEN
        SELECT a.rolpassword INTO v_ver FROM pg_catalog.pg_authid a WHERE a.rolname = p_role;
        PERFORM pass_policy._record_password_change(p_role::text, v_ver);
    END IF;
END
$$;
COMMENT ON FUNCTION _ensure_recorded(name) IS 'Internal: records a password change if the C hook did not';

-- Creates the role_state row of an existing role if missing, and refreshes
-- its role_name (stale after ALTER ROLE ... RENAME until run_maintenance()).
CREATE FUNCTION _ensure_state(p_oid oid)
RETURNS void
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO pass_policy.role_state AS s (role_oid, role_name)
    SELECT a.oid, a.rolname FROM pg_catalog.pg_authid a WHERE a.oid = p_oid
    ON CONFLICT (role_oid) DO UPDATE SET role_name = EXCLUDED.role_name
     WHERE s.role_name IS DISTINCT FROM EXCLUDED.role_name
$$;
COMMENT ON FUNCTION _ensure_state(oid) IS 'Internal: creates the role_state row of a role if missing, refreshes its role_name';

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

-- audit(): granted to pass_policy_admin.  The C hook no longer calls it (a
-- password_rejected row would be rolled back by the ERROR that follows: the
-- hook writes a LOG line instead).  The check below keeps any other caller
-- out even if EXECUTE were granted more widely.
CREATE FUNCTION audit(event_type text, role_name text, details jsonb DEFAULT '{}')
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT coalesce(pass_policy._is_admin(), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied'
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'audit() may only be called by an administrator.';
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
 * Called by the C hook (SPI, as the bootstrap superuser) after a password
 * has been accepted, in the session of whoever runs CREATE/ALTER ROLE ...
 * PASSWORD; EXECUTE is granted to nobody.  Allowed ONLY when the backend is
 * inside the pg_pass_policy hook (_in_password_hook()): PostgreSQL has
 * already checked that the current user may set this role's password
 * (CREATEROLE/ADMIN, self, superuser) before calling the hook.
 * Any direct call is refused, whoever the caller is: a plain user could
 * otherwise reset his own expiry without changing his password, and a
 * non-superuser admin could re-open a superuser account that a superuser had
 * expired (record_password_change does not go through
 * _require_target_allowed()).  The SQL API never needs the direct call:
 * run_maintenance() reconciles pg_authid through _record_password_change().
 */
CREATE FUNCTION record_password_change(role text, verifier text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT coalesce(pass_policy._in_password_hook(), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied to record a password change for role "%"', $1
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'Change the password with ALTER ROLE ... PASSWORD; direct calls are never allowed.';
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
    -- rows of dropped roles (purged by the next run_maintenance()) do not
    -- hold the profile: they are purged here, only existing roles count
    DELETE FROM pass_policy.role_profile rp
     WHERE rp.profile_id = v_id
       AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.oid = rp.role_oid);
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
    -- a non-superuser admin must not be able to assign a lockout-prone or
    -- fast-expiring profile to a privileged role (same rule as rotate/lock)
    v_oid := pass_policy._require_target_allowed(v_role);
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
    -- existing role: same target rule as assign_profile; a dropped role only
    -- has a stale row left for the purge, nothing privileged to protect
    IF v_oid IS NOT NULL THEN
        PERFORM pass_policy._require_target_allowed(v_role);
    END IF;
    DELETE FROM pass_policy.role_profile rp
     WHERE rp.role_oid = v_oid OR (v_oid IS NULL AND rp.role_name = v_role);
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- role gone (row left for the purge): no role_state to recompute;
    -- _refresh_role_state(NULL) would recompute every role
    IF v_oid IS NOT NULL THEN
        PERFORM pass_policy._refresh_role_state(v_oid);
    END IF;
    PERFORM pass_policy._audit('profile_assigned', v_role,
            jsonb_build_object('profile', 'default', 'unassigned', true));
    PERFORM pass_policy._shmem('reload');
END
$$;
COMMENT ON FUNCTION unassign_profile(name) IS 'Removes the profile assignment of a role (back to "default")';

/*
 * Internal: generate a password conforming to the effective profile of a
 * role, set it, record it and apply the VALID UNTIL rule; returns the
 * password.  Shared by rotate_password() and switch_rotation_pair(), which
 * check the caller and the target first (_require_admin(),
 * _require_target_allowed(): p_oid is the OID that check returned).  Not
 * SECURITY DEFINER: only called from those SECURITY DEFINER functions, and
 * EXECUTE is granted to nobody.
 *
 * The generated password exists only in a local variable and in the result
 * of the call: it is never written to a table, the audit, a NOTIFY payload,
 * a RAISE or the server log (see _set_password()).
 * The ALTER ROLE fires the C hook, which checks the policy and calls
 * record_password_change(); _ensure_recorded() covers the case where the
 * hook did not run.
 *
 * Length: p_length NULL (default of the callers) = 24 characters, raised
 * to the min_length of the profile and to the shortest length the
 * generator can build for its class minima (_generator_minimum(): one
 * lower-case, one upper-case and one digit at least, plus a special when
 * min_classes needs it), capped by its max_length (profile_classes_fit
 * keeps that minimum within it); an explicit p_length outside
 * [min_length, max_length] is refused (22023).
 */
CREATE FUNCTION _rotate_role(p_role name, p_oid oid, p_length int,
                             OUT password text, OUT profile text)
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_min int;
    v_max int;
    v_cls int;
    v_len int;
BEGIN
    -- read once: the caller's audit row names the profile actually used
    SELECT p.name, p.min_length, p.max_length,
           pass_policy._generator_minimum(p.min_lower, p.min_upper, p.min_digit,
                                          p.min_special, p.min_classes)
      INTO profile, v_min, v_max, v_cls
      FROM pass_policy.effective_profile(p_role) p;
    IF p_length IS NULL THEN
        v_len := least(greatest(24, v_min, v_cls), v_max);
    ELSIF p_length < v_min OR p_length > v_max THEN
        RAISE EXCEPTION 'pg_pass_policy: password length % is outside the bounds of profile "%"', p_length, profile
              USING ERRCODE = 'invalid_parameter_value',
                    DETAIL = format('Profile "%s" requires %s to %s characters.', profile, v_min, v_max),
                    HINT = 'Omit the length to use the default (24 characters, raised to min_length and to the length the class minima require).';
    ELSE
        v_len := p_length;
    END IF;
    password := pass_policy.generate_password(v_len, profile);
    IF password IS NULL THEN
        RAISE EXCEPTION 'pg_pass_policy: password generation failed';
    END IF;
    PERFORM pass_policy._set_password(p_role, password);
    -- records the change (must_change cleared) if the hook did not
    PERFORM pass_policy._ensure_recorded(p_role);

    PERFORM pass_policy._refresh_role_state(p_oid);
    -- run_maintenance() step d never synchronises an exempt role (it only
    -- lifts a past VALID UNTIL, 'unblock'): a VALID UNTIL written here would
    -- never be updated again, so only a past one is lifted, as with
    -- manage_valid_until = off (this also lifts the bound left by a
    -- previous switch_rotation_pair())
    PERFORM pass_policy._apply_valid_until(p_oid,
              CASE WHEN pass_policy._guc_on('pg_pass_policy.manage_valid_until', true)
                        AND NOT pass_policy._is_exempt(p_role)
                   THEN 'force' ELSE 'unblock' END);
END
$$;
COMMENT ON FUNCTION _rotate_role(name, oid, int) IS 'Internal: generates, sets and records a new password for an already checked role; returns it and the profile used';

/*
 * The password is generated and set by _rotate_role(); it is returned once
 * and never stored or logged.
 */
-- length NULL (default) = 24 characters, raised to the profile min_length
-- and to the length its class minima require (_generator_minimum()), capped
-- by its max_length
CREATE FUNCTION rotate_password(role name, length int DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_role    name := $1;
    v_oid     oid;
    v_profile text;
    v_pwd     text;
BEGIN
    PERFORM pass_policy._require_admin();
    v_oid := pass_policy._require_target_allowed(v_role);

    SELECT r.password, r.profile INTO v_pwd, v_profile
      FROM pass_policy._rotate_role(v_role, v_oid, $2) r;

    PERFORM pass_policy._audit('password_rotated', v_role,
            jsonb_build_object('profile', v_profile, 'length', pg_catalog.length(v_pwd),
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
    -- also refreshes role_state.role_name (current name, after a rename)
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

-- Returns the locked_until written to role_state ('infinity' = manual lock).
CREATE FUNCTION lock_role(role name, duration interval DEFAULT NULL, reason text DEFAULT NULL)
RETURNS timestamptz
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
    -- also refreshes role_state.role_name (current name, after a rename)
    PERFORM pass_policy._ensure_state(v_oid);
    UPDATE pass_policy.role_state s
       SET locked_until = v_until, locked_by = 'manual', lock_reason = $3
     WHERE s.role_oid = v_oid;
    PERFORM pass_policy._shmem('lock', v_role::text, CASE WHEN $2 IS NULL THEN NULL ELSE v_until END);
    PERFORM pass_policy._audit('role_locked', v_role,
            jsonb_build_object('locked_by', 'manual', 'locked_until', v_until, 'reason', $3));
    RETURN v_until;
END
$$;
COMMENT ON FUNCTION lock_role(name, interval, text) IS 'Locks a role (NULL duration = until unlock_role); returns locked_until (infinity = manual)';

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
    -- Like lock_role(), the role_state row is created if missing and locked
    -- (also refreshes role_state.role_name, current name after a rename).
    -- Without a row, the UPDATE below would lock nothing: an automatic lock
    -- of the hook still waiting for its audit could then be written to
    -- role_state by the worker (upsert) after this unlock has committed, and
    -- re-injected by the next reload.  With the row (inserted or locked
    -- here), the worker's upsert waits for this transaction, whose COMMIT
    -- stamps lock_seq before the row lock is released: the worker sees the
    -- stamp and gives up its copy (see SPEC 6.3).
    PERFORM pass_policy._ensure_state(v_oid);
    UPDATE pass_policy.role_state s
       SET locked_until = NULL, locked_by = NULL, lock_reason = NULL
     WHERE s.role_oid = v_oid;
    PERFORM pass_policy._shmem('unlock', v_role::text);
    PERFORM pass_policy._shmem('reset', v_role::text);
    PERFORM pass_policy._audit('role_unlocked', v_role, jsonb_build_object('unlocked_by', 'manual'));
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

-- length NULL (default) = 24 characters, raised to the profile min_length
-- and to the length its class minima require (_generator_minimum()), capped
-- by its max_length
CREATE FUNCTION switch_rotation_pair(pair text, length int DEFAULT NULL)
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

    -- the new active role must not stay bounded by a previous switch
    -- (cleared before the password is set; an ERROR below rolls it back)
    UPDATE pass_policy.rotation_pair r
       SET active_role = v_new, previous_role = v_old, switched_at = now(),
           previous_valid_until = NULL
     WHERE r.pair_name = rp.pair_name;

    SELECT r.password INTO v_pwd FROM pass_policy._rotate_role(v_new, v_new_oid, $2) r;

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
 *  a0. re-map by role name the rows whose role_oid no longer exists
 *      (restore on another cluster, CREATE ROLE ... PASSWORD), then follow
 *      role renames ;
 *  a.  purge rows of roles that no longer exist ;
 *  b.  reconcile pg_authid.rolpassword with the history ;
 *  c.  recompute expires_at / grace_until ;
 *  d.  VALID UNTIL synchronisation (pass_policy.manage_valid_until); when
 *      it is off, and always for an exempt role, only lifts a VALID UNTIL
 *      in the past that the extension wrote itself (expire_password, former
 *      sync) once the password has been changed ('unblock') ;
 *  e.  expiry_warning (max once a day) / password_expired (once), except
 *      for exempt roles ;
 *  f.  automatic unlock of expired locks (current role name; in shared
 *      memory only if the lock there has expired too) ;
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
    v_exempt   oid[];
BEGIN
    PERFORM pass_policy._require_admin();
    -- One pass at a time (worker, pg_cron, manual call): two concurrent
    -- passes would both act on the same rows (duplicate audit rows and
    -- notifications, reconciliation of the same history row).  The second
    -- one waits here, then sees the work of the first.  Transaction-level
    -- lock: released at COMMIT / ROLLBACK, never leaked by an error.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('pg_pass_policy.run_maintenance'));
    -- step b updates password_history.verifier with pg_authid.rolpassword:
    -- keep auto_explain from logging those values (see _set_password)
    IF current_setting('auto_explain.log_min_duration', true) IS NOT NULL THEN
        PERFORM set_config('auto_explain.log_min_duration', '-1', true);
    END IF;

    ---------------------------------------------------------------- a0
    -- Orphaned rows (their OID no longer exists) whose role_name exists with
    -- another OID get that OID: restore on another cluster (OIDs differ,
    -- names are kept).  A row whose OID still exists is never re-mapped,
    -- even if another role now carries its former name (rename, then
    -- creation of a role with the old name): locks, profile and history
    -- follow the OID, and the renames below update the name.
    -- Limit: a role dropped and re-created with the same name between two
    -- passes cannot be told from a restore and inherits the rows.
    FOR r IN
        SELECT 'role_state' AS tbl, s.role_oid AS old_oid, a.oid AS new_oid, s.role_name AS rname
          FROM pass_policy.role_state s JOIN pg_catalog.pg_authid a ON a.rolname = s.role_name
         WHERE a.oid <> s.role_oid
           AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid o WHERE o.oid = s.role_oid)
        UNION ALL
        SELECT 'role_profile', p.role_oid, a.oid, p.role_name
          FROM pass_policy.role_profile p JOIN pg_catalog.pg_authid a ON a.rolname = p.role_name
         WHERE a.oid <> p.role_oid
           AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid o WHERE o.oid = p.role_oid)
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
     WHERE a.rolname = h.role_name AND h.role_oid IS DISTINCT FROM a.oid
       AND (h.role_oid IS NULL
            OR NOT EXISTS (SELECT FROM pg_catalog.pg_authid o WHERE o.oid = h.role_oid));
    -- renames: the OID still exists under another name
    UPDATE pass_policy.role_state s SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = s.role_oid AND a.rolname <> s.role_name;
    UPDATE pass_policy.role_profile p SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = p.role_oid AND a.rolname <> p.role_name;
    UPDATE pass_policy.password_history h SET role_name = a.rolname
      FROM pg_catalog.pg_authid a
     WHERE a.oid = h.role_oid AND a.rolname <> h.role_name;

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
    -- A row still without OID (CREATE ROLE ... PASSWORD) whose role is
    -- visible now but was not when step a0 ran (READ COMMITTED: every
    -- statement takes a new snapshot) is kept: the next pass maps it.
    DELETE FROM pass_policy.password_history h
     WHERE (h.role_oid IS NULL
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = h.role_name))
        OR (h.role_oid IS NOT NULL
            AND NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.oid = h.role_oid));
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
            -- expected mismatch: the hook recorded its own verifier (other salt).
            -- Limit (SPEC 11, revue finale 4 H4): a real change made without
            -- the hook (enforce_database = off outside the database,
            -- enabled = off, exempt role) between that change and this pass
            -- cannot be told apart from the salt gap without the clear text,
            -- and is taken for it: no audit row, no new change date.
            UPDATE pass_policy.password_history h SET verifier = r.rolpassword WHERE h.id = r.hid;
            INSERT INTO pass_policy.role_state AS s (role_oid, role_name, password_changed_at)
            VALUES (r.oid, r.rname, r.hchanged)
            ON CONFLICT (role_oid) DO UPDATE SET verifier_pending = false;
            CONTINUE;                       -- bookkeeping only, not reported
        ELSIF r.hverifier <> r.rolpassword THEN
            -- the password was changed without going through the hook
            INSERT INTO pass_policy.password_history (role_oid, role_name, verifier, changed_at)
            VALUES (r.oid, r.rname, r.rolpassword, now());
            PERFORM pass_policy._trim_history(r.oid);
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
    -- Exempt login roles, evaluated once per pass (steps d and e).
    v_exempt := ARRAY(SELECT a.oid FROM pg_catalog.pg_authid a
                       WHERE a.rolcanlogin AND pass_policy._is_exempt(a.rolname));
    -- 'sync' only when the extension manages VALID UNTIL for the role
    -- (manage_valid_until = on, role not exempt).  Otherwise only roles whose
    -- current VALID UNTIL was written by the extension (= valid_until_synced:
    -- expire_password, former sync) and whose password has been changed
    -- since (must_change cleared) are considered, in 'unblock' mode
    -- (rewrites only a VALID UNTIL already in the past).  Exempt roles are
    -- kept for 'unblock', as in rotate_password(): their password may be
    -- changed by a plain ALTER ROLE, which the hook does not record.
    FOR r IN
        SELECT s.role_oid, a.rolname::text AS rname,
               v_manage AND NOT x.exempt AS do_sync
          FROM pass_policy.role_state s
          JOIN pg_catalog.pg_authid a ON a.oid = s.role_oid
         CROSS JOIN LATERAL (SELECT a.oid = ANY (v_exempt) AS exempt) x
         WHERE a.rolcanlogin
           AND ((v_manage AND NOT x.exempt)
                OR (NOT s.must_change AND a.rolvaliduntil IS NOT DISTINCT FROM s.valid_until_synced))
    LOOP
        v_res := pass_policy._apply_valid_until(r.role_oid, CASE WHEN r.do_sync THEN 'sync' ELSE 'unblock' END);
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
           AND NOT (a.oid = ANY (v_exempt))
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
    -- The shared memory is keyed by the current role name: taken from
    -- pg_authid (role_state.role_name is refreshed by step a0 too, but the
    -- name used for the unlock and the audit must never be a stale one).
    -- Rows of dropped roles were purged by step a.
    -- 'unlock_expired': the shared memory may hold a newer automatic lock
    -- that role_state does not know yet (new failures after the expiry,
    -- before or during this pass): only an expired lock is lifted there.
    FOR r IN
        UPDATE pass_policy.role_state s
           SET locked_until = NULL, locked_by = NULL, lock_reason = NULL,
               role_name = a.rolname
          FROM pg_catalog.pg_authid a
         WHERE a.oid = s.role_oid AND s.locked_until < now()
        RETURNING a.rolname::text AS rname
    -- An unlock refused by the shared memory (active newer lock, false) is
    -- neither audited nor returned: the role is still locked, and the
    -- worker copies the newer lock to role_state at its next cycle.
    LOOP
        IF pass_policy._shmem('unlock_expired', r.rname) THEN
            PERFORM pass_policy._audit('role_unlocked', r.rname, '{"unlocked_by":"auto"}');
            action := 'role_unlocked'; role_name := r.rname; details := '{"unlocked_by":"auto"}';
            v_actions := v_actions + 1;
            RETURN NEXT;
        END IF;
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

/*
 * rebind_restored_roles(): explicit repair after restoring the extension
 * tables into ANOTHER cluster (pg_dump / pg_restore), where the role OIDs
 * differ.  run_maintenance() step a0 cannot do it: in a live cluster OIDs
 * are stable, so a row whose OID exists under another name is a rename and
 * the OID wins (SPEC §11 S3).  After a restore, the former OID of a role X
 * may belong to another role Y: a0 would relabel the rows of X as rows of Y.
 *
 * Every row of role_state, role_profile and password_history whose pair
 * (role_oid, role_name) matches no pg_authid row is rebound BY NAME: the
 * name exists under another OID -> the row takes that OID ('rebind'); the
 * name does not exist -> the row is purged ('purge').  A rebound row whose
 * target OID already holds a matching row is purged too (the matching row
 * wins).  For role_state and role_profile (primary key role_oid), all the
 * mismatched rows are first removed (DELETE ... RETURNING, kept in an
 * array) and then inserted again (INSERT ... ON CONFLICT DO NOTHING), so
 * that two rows exchanging their OIDs are handled whatever the order.
 * rotation_pair holds role names only: nothing to rebind (run_maintenance()
 * purges the pairs whose roles do not exist).
 *
 * To be called once, right after the restore and BEFORE the first
 * run_maintenance() (worker_interval = 0 and enabled = off meanwhile, see
 * README).  Superuser only: it rewrites the rows of every role.
 */
CREATE FUNCTION rebind_restored_roles()
RETURNS TABLE (action text, role_name text, details jsonb)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_tbl     text;
    v_rows    jsonb[];
    v_kept    oid[];
    j         jsonb;
    r         record;
    v_rebound int := 0;
    v_purged  int := 0;
BEGIN
    PERFORM pass_policy._require_admin();
    IF NOT coalesce((SELECT x.rolsuper FROM pg_catalog.pg_roles x WHERE x.rolname = session_user), false) THEN
        RAISE EXCEPTION 'pg_pass_policy: permission denied'
              USING ERRCODE = 'insufficient_privilege',
                    HINT = 'rebind_restored_roles() requires a superuser.';
    END IF;
    -- not concurrently with a maintenance pass (same lock as run_maintenance)
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('pg_pass_policy.run_maintenance'));

    FOREACH v_tbl IN ARRAY ARRAY['role_state', 'role_profile']
    LOOP
        EXECUTE format(
            'WITH c AS (SELECT t.role_oid AS old_oid, a.oid AS new_oid'
            '             FROM pass_policy.%1$I t'
            '             LEFT JOIN pg_catalog.pg_authid a ON a.rolname = t.role_name'
            '            WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_authid o'
            '                               WHERE o.oid = t.role_oid AND o.rolname = t.role_name)),'
            '     d AS (DELETE FROM pass_policy.%1$I t USING c WHERE t.role_oid = c.old_oid'
            '           RETURNING pg_catalog.to_jsonb(t) OPERATOR(pg_catalog.||)'
            '                     pg_catalog.jsonb_build_object(''new_oid'', c.new_oid) AS j)'
            ' SELECT pg_catalog.array_agg(d.j) FROM d', v_tbl)
          INTO v_rows;
        IF v_rows IS NULL THEN
            CONTINUE;
        END IF;
        -- all the mismatched rows are gone: insert them again under their new OID
        EXECUTE format(
            'WITH i AS (INSERT INTO pass_policy.%1$I'
            '           SELECT (pg_catalog.jsonb_populate_record(NULL::pass_policy.%1$I,'
            '                   u.j OPERATOR(pg_catalog.||) pg_catalog.jsonb_build_object(''role_oid'', u.j->''new_oid''))).*'
            '             FROM pg_catalog.unnest($1) u(j)'
            '            WHERE u.j->>''new_oid'' IS NOT NULL'
            '           ON CONFLICT (role_oid) DO NOTHING'
            '           RETURNING role_oid)'
            ' SELECT pg_catalog.array_agg(i.role_oid) FROM i', v_tbl)
          INTO v_kept USING v_rows;
        FOREACH j IN ARRAY v_rows
        LOOP
            role_name := j->>'role_name';
            IF j->>'new_oid' IS NOT NULL AND (j->>'new_oid')::oid = ANY (coalesce(v_kept, '{}')) THEN
                action := 'rebind';
                details := jsonb_build_object('table', v_tbl, 'old_oid', (j->>'role_oid')::oid,
                                              'new_oid', (j->>'new_oid')::oid);
                v_rebound := v_rebound + 1;
                -- the same OID cannot be reported twice (one row kept per OID)
                v_kept := array_remove(v_kept, (j->>'new_oid')::oid);
            ELSE
                action := 'purge';
                details := jsonb_build_object('table', v_tbl, 'old_oid', (j->>'role_oid')::oid,
                                              'reason', CASE WHEN j->>'new_oid' IS NULL
                                                             THEN 'role does not exist'
                                                             ELSE 'role already has a row' END);
                v_purged := v_purged + 1;
            END IF;
            RETURN NEXT;
        END LOOP;
    END LOOP;

    -- password_history: no key on role_oid, plain UPDATE / DELETE
    FOR r IN
        WITH u AS (
            UPDATE pass_policy.password_history h SET role_oid = a.oid
              FROM pg_catalog.pg_authid a
             WHERE a.rolname = h.role_name AND h.role_oid IS DISTINCT FROM a.oid
            RETURNING h.role_name AS rname)
        SELECT u.rname, count(*) AS n FROM u GROUP BY u.rname ORDER BY u.rname
    LOOP
        action := 'rebind'; role_name := r.rname;
        details := jsonb_build_object('table', 'password_history', 'rows', r.n);
        v_rebound := v_rebound + r.n;
        RETURN NEXT;
    END LOOP;
    FOR r IN
        WITH d AS (
            DELETE FROM pass_policy.password_history h
             WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_authid a WHERE a.rolname = h.role_name)
            RETURNING h.role_name AS rname)
        SELECT d.rname, count(*) AS n FROM d GROUP BY d.rname ORDER BY d.rname
    LOOP
        action := 'purge'; role_name := r.rname;
        details := jsonb_build_object('table', 'password_history', 'rows', r.n,
                                      'reason', 'role does not exist');
        v_purged := v_purged + r.n;
        RETURN NEXT;
    END LOOP;

    IF v_rebound > 0 OR v_purged > 0 THEN
        PERFORM pass_policy._audit('maintenance', NULL,
                jsonb_build_object('rebind_restored_roles',
                                   jsonb_build_object('rebound_rows', v_rebound, 'purged_rows', v_purged)));
        -- locks and profiles are keyed by name in shared memory
        PERFORM pass_policy._shmem('reload');
    END IF;
    RETURN;
END
$$;
COMMENT ON FUNCTION rebind_restored_roles() IS 'After a restore into another cluster: rebinds by role name the rows whose (role_oid, role_name) matches no role, purges those of missing roles (superuser)';

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
       END AS status,
       q.role_oid
  FROM (SELECT r.oid AS role_oid, r.rolname::text AS role_name, e.name AS profile, e.max_age, e.warn_before,
               s.password_changed_at, coalesce(s.must_change, false) AS must_change,
               CASE WHEN s.must_change THEN s.expires_at
                    ELSE s.password_changed_at + e.max_age END AS expires_at,
               CASE WHEN s.must_change THEN s.grace_until
                    ELSE s.password_changed_at + e.max_age + e.grace_period END AS grace_until,
               greatest(s.locked_until, f.locked_until) AS locked_until,
               coalesce(f.failed_count, 0) AS failed_count
          FROM pg_catalog.pg_roles r
          JOIN _role_effective_profile e ON e.role_oid = r.oid
          LEFT JOIN role_state s ON s.role_oid = r.oid
          LEFT JOIN failed_attempts() f ON f.role_name = r.rolname
         WHERE r.rolcanlogin) q;
COMMENT ON VIEW v_role_status IS 'Password and lock status of every login role (role_oid: join key for role_state)';

CREATE VIEW v_expiring AS
SELECT * FROM v_role_status WHERE status IN ('warning', 'grace', 'expired');
COMMENT ON VIEW v_expiring IS 'Login roles whose password is about to expire, in grace period or expired';

-- Joined by OID: role_state.role_name may still hold the former name after
-- ALTER ROLE ... RENAME (until run_maintenance() or the next lock_role()).
CREATE VIEW v_locked AS
SELECT v.role_name, v.locked_until, s.locked_by, s.lock_reason, v.failed_count
  FROM v_role_status v
  LEFT JOIN role_state s ON s.role_oid = v.role_oid
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
 * - nothing to PUBLIC: the SPI queries of the C hook run as the bootstrap
 *   superuser (ppp_spi_begin(), src/policy.c), whoever changes a password,
 *   so neither USAGE on the schema nor EXECUTE on effective_profile(),
 *   record_password_change() or audit() is needed by ordinary users ;
 *   record_password_change() keeps its _in_password_hook() guard and
 *   audit() its _is_admin() check as defence in depth ;
 * - viewer: SELECT on tables and views, except password_history.verifier
 *   (column grant: the hashes are offline-cracking material) ;
 * - admin: member of viewer + EXECUTE on the administration API ;
 * - shmem_* and internal _* functions: no grant (called by SECURITY DEFINER
 *   code only).
 */
REVOKE ALL ON SCHEMA pass_policy FROM PUBLIC;
GRANT USAGE ON SCHEMA pass_policy TO pass_policy_viewer, pass_policy_admin;

REVOKE ALL ON ALL TABLES IN SCHEMA pass_policy FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pass_policy FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA pass_policy FROM PUBLIC;

GRANT SELECT ON profile, role_profile, role_state, dictionary, audit_log, rotation_pair,
                v_role_status, v_expiring, v_locked, v_recent_audit
   TO pass_policy_viewer, pass_policy_admin;
GRANT SELECT (id, role_oid, role_name, changed_at) ON password_history
   TO pass_policy_viewer, pass_policy_admin;

-- read-only API; needed by the views (failed_attempts, worker_status)
GRANT EXECUTE ON FUNCTION effective_profile(name), failed_attempts(), worker_status()
   TO pass_policy_viewer, pass_policy_admin;
-- _is_privileged(): exposed so that clients (web, CLI) can filter their role
-- lists with the very predicate _require_target_allowed() enforces
GRANT EXECUTE ON FUNCTION _is_privileged(oid) TO pass_policy_viewer, pass_policy_admin;
-- record_password_change(): no grant (called by the C hook as superuser only)

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
    load_dictionary(text[]),
    audit(text, text, jsonb)
   TO pass_policy_admin;
