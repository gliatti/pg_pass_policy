/*-------------------------------------------------------------------------
 *
 * lockout.c
 *		Account lockout after repeated authentication failures.
 *
 * The ClientAuthentication_hook runs in a backend that is not fully
 * initialised yet: no transaction, no catalog access, no SPI.  Everything it
 * needs therefore lives in shared memory (ppp_role_hash), which is filled
 * by the background worker (profile parameters, persisted locks) and read
 * back by the worker to write audit rows and role_state (see worker.c).
 *
 * This file also provides the C functions exposed in SQL:
 *	 failed_attempts(), shmem_reload(), shmem_lock_role(),
 *	 shmem_unlock_role(), shmem_reset_failures().
 *
 * See docs/SPEC.md, sections 4 and 6.3.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <signal.h>

#include "fmgr.h"
#include "funcapi.h"
#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"

#include "pg_pass_policy.h"
#include "compat.h"

PG_FUNCTION_INFO_V1(ppp_failed_attempts);
PG_FUNCTION_INFO_V1(ppp_shmem_reload);
PG_FUNCTION_INFO_V1(ppp_shmem_lock_role);
PG_FUNCTION_INFO_V1(ppp_shmem_unlock_role);
PG_FUNCTION_INFO_V1(ppp_shmem_reset_failures);

/* Safe defaults until the worker has read the "default" profile */
#define PPP_DEFAULT_MAX_FAILURES		5
#define PPP_DEFAULT_FAILURE_WINDOW		900
#define PPP_DEFAULT_LOCK_DURATION		1800

static ClientAuthentication_hook_type prev_client_auth_hook = NULL;

static void ppp_client_auth_hook(Port *port, int status);


/*
 * Copy a role name into a hash key, truncated like the server does for
 * port->user_name (plain byte truncation to NAMEDATALEN - 1).
 */
static void
ppp_make_key(pppRoleKey *key, const char *rolename)
{
	memset(key, 0, sizeof(pppRoleKey));
	strlcpy(key->rolename, rolename, NAMEDATALEN);
}

/*
 * Initialise a freshly entered hash entry with the default parameters.
 * Caller must hold ppp_shared->lock exclusively.
 */
static void
ppp_init_entry(pppRoleEntry *entry)
{
	entry->max_failures = ppp_shared->default_max_failures;
	entry->failure_window_secs = ppp_shared->default_failure_window_secs;
	entry->lock_duration_secs = ppp_shared->default_lock_duration_secs;
	entry->from_profile = false;
	entry->failed_count = 0;
	entry->first_failure_at = 0;
	entry->last_failure_at = 0;
	entry->locked_until = 0;
	entry->lock_pending_audit = false;
	entry->pending_failures = 0;
}

/*
 * Find or create the entry of a role.  Returns NULL when the hash is full
 * (ppp_max_tracked_roles entries).  Caller must hold ppp_shared->lock
 * exclusively.
 *
 * The explicit size check is needed: a shared hash can grow beyond its
 * max_size as long as the shared memory segment has free space left.
 */
static pppRoleEntry *
ppp_enter_role(const char *rolename)
{
	pppRoleKey	key;
	pppRoleEntry *entry;
	bool		found;

	ppp_make_key(&key, rolename);
	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry)
		return entry;

	if (hash_get_num_entries(ppp_role_hash) >= ppp_max_tracked_roles)
		return NULL;

	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key,
										 HASH_ENTER_NULL, &found);
	if (entry && !found)
		ppp_init_entry(entry);
	return entry;
}

/*
 * Is the lock of an entry active at time "now"?
 */
static inline bool
ppp_is_locked(const pppRoleEntry *entry, TimestampTz now)
{
	if (entry->locked_until == 0)
		return false;
	if (entry->locked_until == DT_NOEND)
		return true;
	return entry->locked_until > now;
}

/*
 * Called from the shmem_startup_hook (pg_pass_policy.c), after ppp_shared
 * has been allocated and its LWLock assigned.  The caller holds
 * AddinShmemInitLock.
 *
 * The key is a NUL-terminated char[NAMEDATALEN]; HASH_STRINGS (available
 * since PG 14) compares at most keysize - 1 bytes with strncmp, so the key
 * does not need to be zero-padded.  We zero it anyway (ppp_make_key).
 *
 * The hash size must be accounted for in ppp_shmem_size():
 *	 hash_estimate_size(ppp_max_tracked_roles, sizeof(pppRoleEntry)).
 */
void
ppp_lockout_shmem_init(void)
{
	HASHCTL		info;

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pppRoleKey);
	info.entrysize = sizeof(pppRoleEntry);

	ppp_role_hash = ShmemInitHash("pg_pass_policy roles",
								  ppp_max_tracked_roles,
								  ppp_max_tracked_roles,
								  &info,
								  HASH_ELEM | HASH_STRINGS);

	/*
	 * Without EXEC_BACKEND, this runs once in the postmaster.  With
	 * EXEC_BACKEND, it runs again in every child: the shared state must not
	 * be reset there.
	 */
	if (!IsUnderPostmaster && ppp_shared != NULL)
	{
		ppp_shared->default_max_failures = PPP_DEFAULT_MAX_FAILURES;
		ppp_shared->default_failure_window_secs = PPP_DEFAULT_FAILURE_WINDOW;
		ppp_shared->default_lock_duration_secs = PPP_DEFAULT_LOCK_DURATION;
		/* force a first load of profiles and persisted locks */
		pg_atomic_init_u32(&ppp_shared->reload_requested, 1);
	}
}

/*
 * Install the authentication hook.  Called from _PG_init.
 */
void
ppp_lockout_init(void)
{
	prev_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = ppp_client_auth_hook;
}

/*
 * ClientAuthentication_hook: see SPEC 6.3.
 *
 * - a locked role is refused with FATAL whatever the authentication result,
 *   so that a correct password cannot be told apart from a wrong one while
 *   the role is locked;
 * - STATUS_ERROR is counted as a failure;
 * - STATUS_EOF (client closed the connection when asked for a password, as
 *   psql does before prompting) is NOT counted: no password was tried.
 */
static void
ppp_client_auth_hook(Port *port, int status)
{
	const char *rolename;
	TimestampTz now;
	TimestampTz locked_until = 0;
	bool		refuse = false;
	bool		just_locked = false;
	bool		hash_full = false;
	int			failed_count = 0;
	pppRoleKey	key;
	pppRoleEntry *entry;

	rolename = port ? port->user_name : NULL;

	if (!ppp_enabled || ppp_shared == NULL || ppp_role_hash == NULL ||
		rolename == NULL || rolename[0] == '\0' ||
		ppp_role_is_exempt(rolename))
	{
		if (prev_client_auth_hook)
			prev_client_auth_hook(port, status);
		return;
	}

	now = GetCurrentTimestamp();
	ppp_make_key(&key, rolename);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);

	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry == NULL && status == STATUS_ERROR)
	{
		entry = ppp_enter_role(rolename);
		if (entry == NULL)
			hash_full = true;
	}

	if (entry != NULL)
	{
		if (ppp_is_locked(entry, now))
		{
			refuse = true;
			locked_until = entry->locked_until;
		}
		else
		{
			if (entry->locked_until != 0)
			{
				/* lock expired: start afresh */
				entry->locked_until = 0;
				entry->failed_count = 0;
				entry->first_failure_at = 0;
				entry->lock_pending_audit = false;
			}

			if (status == STATUS_OK)
			{
				entry->failed_count = 0;
				entry->first_failure_at = 0;
			}
			else if (status == STATUS_ERROR)
			{
				/*
				 * Restart counting when the window has elapsed.  A window <= 0
				 * means "no window": failures add up until a success.
				 */
				if (entry->failed_count == 0 ||
					entry->first_failure_at == 0 ||
					(entry->failure_window_secs > 0 &&
					 now - entry->first_failure_at >
					 (int64) entry->failure_window_secs * USECS_PER_SEC))
				{
					entry->failed_count = 0;
					entry->first_failure_at = now;
				}
				entry->failed_count++;
				entry->last_failure_at = now;
				entry->pending_failures++;

				if (entry->max_failures > 0 &&
					entry->failed_count >= entry->max_failures)
				{
					if (entry->lock_duration_secs < 0)
						entry->locked_until = DT_NOEND;
					else
						entry->locked_until = TimestampTzPlusMilliseconds(now,
																		  (int64) entry->lock_duration_secs * 1000);
					entry->lock_pending_audit = true;
					just_locked = true;
					locked_until = entry->locked_until;
					failed_count = entry->failed_count;
				}
			}
		}
	}

	LWLockRelease(ppp_shared->lock);

	if (hash_full)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "cannot track authentication failures of role \"%s\": too many tracked roles",
						rolename),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));

	if (just_locked && ppp_log_events)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "role \"%s\" locked after %d failed attempts",
						rolename, failed_count)));

	if (refuse)
	{
		if (locked_until == DT_NOEND)
			ereport(FATAL,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg("role \"%s\" is locked by pg_pass_policy", rolename),
					 errdetail("The role is locked until manual unlock.")));
		else
			ereport(FATAL,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg("role \"%s\" is locked by pg_pass_policy", rolename),
					 errdetail("The role is locked until %s.",
							   timestamptz_to_str(locked_until))));
	}

	if (prev_client_auth_hook)
		prev_client_auth_hook(port, status);
}

/* ------------------------------------------------------------------------
 * SQL-callable functions
 * ------------------------------------------------------------------------
 */

static void
ppp_check_shmem(void)
{
	if (ppp_shared == NULL || ppp_role_hash == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_pass_policy shared memory is not initialized"),
				 errhint("Add pg_pass_policy to shared_preload_libraries and restart the server.")));
}

static void
ppp_require_superuser(const char *funcname)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for function %s", funcname),
				 errdetail("Only superusers can call this function directly; use the pg_pass_policy administration functions.")));
}

/* local copy of a hash entry, built under the lock */
typedef struct pppAttemptRow
{
	char		rolename[NAMEDATALEN];
	int32		failed_count;
	TimestampTz first_failure_at;
	TimestampTz last_failure_at;
	TimestampTz locked_until;
} pppAttemptRow;

/*
 * failed_attempts() RETURNS TABLE(role_name text, failed_count int,
 *	 first_failure_at timestamptz, last_failure_at timestamptz,
 *	 locked_until timestamptz)
 *
 * Only roles with failures or an active lock are returned.  Timestamps at
 * 0 are returned as NULL; a manual lock (DT_NOEND) as 'infinity'.
 *
 * The materialize-mode boilerplate is written by hand (instead of
 * InitMaterializedSRF/SetSingleFuncCall) so that it works unchanged on
 * PG 14 to 18.
 */
Datum
ppp_failed_attempts(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	pppAttemptRow *rows;
	int			nrows = 0;
	int			maxrows;
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	TimestampTz now;
	int			i;

	ppp_check_shmem();

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not allowed in this context")));

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");
	if (tupdesc->natts != 5)
		elog(ERROR, "failed_attempts() must be declared with 5 output columns");
	tupdesc = CreateTupleDescCopy(tupdesc);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	/* copy the interesting entries under a shared lock, no palloc inside */
	maxrows = ppp_max_tracked_roles > 0 ? ppp_max_tracked_roles : 1;
	rows = (pppAttemptRow *) palloc(sizeof(pppAttemptRow) * maxrows);
	now = GetCurrentTimestamp();

	LWLockAcquire(ppp_shared->lock, LW_SHARED);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		bool		locked = ppp_is_locked(entry, now);

		if (entry->failed_count <= 0 && !locked)
			continue;
		if (nrows >= maxrows)
		{
			hash_seq_term(&seq);
			break;
		}
		strlcpy(rows[nrows].rolename, entry->key.rolename, NAMEDATALEN);
		rows[nrows].failed_count = entry->failed_count;
		rows[nrows].first_failure_at = entry->first_failure_at;
		rows[nrows].last_failure_at = entry->last_failure_at;
		rows[nrows].locked_until = locked ? entry->locked_until : 0;
		nrows++;
	}
	LWLockRelease(ppp_shared->lock);

	for (i = 0; i < nrows; i++)
	{
		Datum		values[5];
		bool		nulls[5];

		memset(nulls, 0, sizeof(nulls));
		values[0] = CStringGetTextDatum(rows[i].rolename);
		values[1] = Int32GetDatum(rows[i].failed_count);
		if (rows[i].first_failure_at != 0)
			values[2] = TimestampTzGetDatum(rows[i].first_failure_at);
		else
			nulls[2] = true;
		if (rows[i].last_failure_at != 0)
			values[3] = TimestampTzGetDatum(rows[i].last_failure_at);
		else
			nulls[3] = true;
		if (rows[i].locked_until != 0)
			values[4] = TimestampTzGetDatum(rows[i].locked_until);	/* DT_NOEND = infinity */
		else
			nulls[4] = true;

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	pfree(rows);

	return (Datum) 0;
}

/*
 * shmem_reload() RETURNS void
 *
 * Ask the worker to reload the lockout parameters of the profiles and the
 * persisted locks of role_state into shared memory.  Sets reload_requested
 * and sends SIGHUP to the worker (whose PID is published in
 * ppp_shared->worker_pid); the worker treats SIGHUP as "reload the
 * configuration file and run a cycle now".  Not signalled when called from
 * the worker itself (run_maintenance() calls shmem_reload()), which would
 * otherwise loop forever.
 */
Datum
ppp_shmem_reload(PG_FUNCTION_ARGS)
{
	pid_t		pid;

	ppp_check_shmem();

	pg_atomic_write_u32(&ppp_shared->reload_requested, 1);

	LWLockAcquire(ppp_shared->lock, LW_SHARED);
	pid = ppp_shared->worker_pid;
	LWLockRelease(ppp_shared->lock);

	if (pid > 0 && pid != MyProcPid)
	{
		if (kill(pid, SIGHUP) != 0)
			ereport(DEBUG1,
					(errmsg(PPP_LOG_PREFIX "could not signal worker process %d: %m",
							(int) pid)));
	}

	PG_RETURN_VOID();
}

static void
ppp_text_to_rolename(text *t, char *buf)
{
	char	   *s = text_to_cstring(t);

	if (s[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("role name must not be empty")));
	strlcpy(buf, s, NAMEDATALEN);
	pfree(s);
}

/*
 * shmem_lock_role(role text, until timestamptz) RETURNS void
 *
 * until NULL (or 'infinity') = locked until manual unlock.
 */
Datum
ppp_shmem_lock_role(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	TimestampTz until;
	pppRoleEntry *entry;

	ppp_require_superuser("shmem_lock_role");
	ppp_check_shmem();

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("role name must not be NULL")));
	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);

	if (PG_ARGISNULL(1))
		until = DT_NOEND;
	else
	{
		until = PG_GETARG_TIMESTAMPTZ(1);
		if (TIMESTAMP_IS_NOEND(until))
			until = DT_NOEND;
		else if (TIMESTAMP_IS_NOBEGIN(until))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("lock end time must not be -infinity")));
	}

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	entry = ppp_enter_role(rolename);
	if (entry != NULL)
	{
		entry->locked_until = until;
		/* the SQL caller writes its own audit row */
		entry->lock_pending_audit = false;
	}
	LWLockRelease(ppp_shared->lock);

	if (entry == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("cannot lock role \"%s\" in shared memory: too many tracked roles",
						rolename),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));

	PG_RETURN_VOID();
}

/*
 * shmem_unlock_role(role text) RETURNS void
 *
 * Removes the lock; the failure counter is left alone (see
 * shmem_reset_failures).
 */
Datum
ppp_shmem_unlock_role(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	pppRoleKey	key;
	pppRoleEntry *entry;

	ppp_require_superuser("shmem_unlock_role");
	ppp_check_shmem();

	if (PG_ARGISNULL(0))
		PG_RETURN_VOID();
	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);
	ppp_make_key(&key, rolename);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry != NULL)
	{
		entry->locked_until = 0;
		entry->lock_pending_audit = false;
	}
	LWLockRelease(ppp_shared->lock);

	PG_RETURN_VOID();
}

/*
 * shmem_reset_failures(role text) RETURNS void
 *
 * Resets the failure counter.  Failures not yet written to the audit log
 * (pending_failures) are kept: they did happen.
 */
Datum
ppp_shmem_reset_failures(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	pppRoleKey	key;
	pppRoleEntry *entry;

	ppp_require_superuser("shmem_reset_failures");
	ppp_check_shmem();

	if (PG_ARGISNULL(0))
		PG_RETURN_VOID();
	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);
	ppp_make_key(&key, rolename);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry != NULL)
	{
		entry->failed_count = 0;
		entry->first_failure_at = 0;
		entry->last_failure_at = 0;
	}
	LWLockRelease(ppp_shared->lock);

	PG_RETURN_VOID();
}
