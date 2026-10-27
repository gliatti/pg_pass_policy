/*-------------------------------------------------------------------------
 *
 * worker.c
 *		pg_pass_policy background worker: periodic maintenance and
 *		synchronisation between the shared memory hash (lockout.c) and the
 *		pg_pass_policy tables.
 *
 * Each cycle, in pg_pass_policy.database:
 *	 1. SELECT * FROM pass_policy.run_maintenance()  (own transaction;
 *		skipped when pg_pass_policy.worker_interval = 0)
 *	 2. shared memory synchronisation (own transaction):
 *		a. audit rows for pending failures / locks, locks copied to
 *		   role_state;
 *		b. expired locks cleared, inactive entries purged;
 *		c. when requested (shmem_reload() or first cycle): lockout
 *		   parameters reloaded from the profiles, persisted locks re-injected
 *		   from role_state.
 *
 * Signals: SIGHUP = reload the configuration file and run a cycle now
 * (shmem_reload() sends it); SIGTERM = exit.
 *
 * Any error raised during a cycle is caught, logged as WARNING and the
 * transaction aborted, so that the worker does not die and restart in a
 * loop.
 *
 * See docs/SPEC.md, sections 6.3 and 6.4.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/pg_type.h"
#include "commands/extension.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"
#include "utils/timestamp.h"

#include "pg_pass_policy.h"
#include "compat.h"

/* inactive entries without lock are purged after this delay */
#define PPP_PURGE_AFTER_SECS	(24 * 60 * 60)

/* copy of an entry with something to write to the tables */
typedef struct pppPendingRow
{
	char		rolename[NAMEDATALEN];
	int32		pending_failures;
	bool		lock_pending_audit;
	int32		failed_count;
	TimestampTz last_failure_at;
	TimestampTz locked_until;
} pppPendingRow;

/* lockout parameters of a role, read from the profiles */
typedef struct pppProfileRow
{
	char		rolename[NAMEDATALEN];
	int32		max_failures;
	int32		failure_window_secs;
	int32		lock_duration_secs;
} pppProfileRow;

/* persisted lock read from role_state */
typedef struct pppLockRow
{
	char		rolename[NAMEDATALEN];
	TimestampTz locked_until;
} pppLockRow;

static MemoryContext ppp_worker_cxt = NULL;

/*
 * A reload was requested and has not been carried out yet (extension not
 * installed yet, or error).  Kept locally instead of re-setting
 * ppp_shared->reload_requested, which would make the main loop run again
 * immediately, in a busy loop.  Retried on the next timed cycle.
 */
static bool ppp_reload_pending = false;


/*
 * Register the worker.  Called from _PG_init (only when loaded through
 * shared_preload_libraries).
 */
void
ppp_worker_register(void)
{
	BackgroundWorker worker;

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 10;
	snprintf(worker.bgw_library_name, BGW_MAXLEN, "%s", PPP_LIBRARY_NAME);
	snprintf(worker.bgw_function_name, BGW_MAXLEN, "ppp_worker_main");
	snprintf(worker.bgw_name, BGW_MAXLEN, "pg_pass_policy worker");
	snprintf(worker.bgw_type, BGW_MAXLEN, "pg_pass_policy worker");
	worker.bgw_main_arg = (Datum) 0;
	worker.bgw_notify_pid = 0;

	RegisterBackgroundWorker(&worker);
}

/*
 * on_shmem_exit callback: unpublish our PID.
 */
static void
ppp_worker_on_exit(int code, Datum arg)
{
	if (ppp_shared != NULL && ppp_shared->worker_pid == MyProcPid)
		ppp_shared->worker_pid = 0;
}

static inline Datum
ppp_text_datum(const char *s)
{
	return CStringGetTextDatum(s);
}

/*
 * Run a cycle step inside its own transaction; errors are turned into a
 * WARNING.  Returns true on success.
 */
static bool
ppp_run_in_xact(const char *what, void (*step) (void))
{
	MemoryContext oldcxt = CurrentMemoryContext;
	volatile bool ok = true;

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();

	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");
		PushActiveSnapshot(GetTransactionSnapshot());

		if (OidIsValid(get_extension_oid(PPP_LIBRARY_NAME, true)))
			step();
		else
			elog(DEBUG1, PPP_LOG_PREFIX "extension not installed in database \"%s\", nothing to do",
				 ppp_database);

		SPI_finish();
		PopActiveSnapshot();
		CommitTransactionCommand();
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(ppp_worker_cxt);
		edata = CopyErrorData();
		FlushErrorState();

		ereport(WARNING,
				(errmsg(PPP_LOG_PREFIX "worker %s failed: %s", what, edata->message),
				 edata->detail ? errdetail_internal("%s", edata->detail) : 0,
				 edata->context ? errcontext("%s", edata->context) : 0));
		FreeErrorData(edata);

		AbortCurrentTransaction();
		ok = false;
	}
	PG_END_TRY();

	MemoryContextSwitchTo(oldcxt);
	pgstat_report_stat(false);

	return ok;
}

/* ------------------------------------------------------------------------
 * Step 1: run_maintenance()
 * ------------------------------------------------------------------------
 */
static void
ppp_step_maintenance(void)
{
	int			ret;

	ret = SPI_execute("SELECT * FROM pass_policy.run_maintenance()", false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "run_maintenance() returned SPI code %d", ret);

	elog(DEBUG1, PPP_LOG_PREFIX "run_maintenance() returned " UINT64_FORMAT " rows",
		 SPI_processed);
}

/* ------------------------------------------------------------------------
 * Step 2a: pending audit rows and locks -> tables
 * ------------------------------------------------------------------------
 */
static void
ppp_sync_pending(void)
{
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	pppPendingRow *rows;
	int			nrows = 0;
	int			maxrows = ppp_max_tracked_roles > 0 ? ppp_max_tracked_roles : 1;
	int			i;

	rows = (pppPendingRow *) palloc(sizeof(pppPendingRow) * maxrows);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		if (!entry->lock_pending_audit && entry->pending_failures <= 0)
			continue;
		if (nrows >= maxrows)
		{
			hash_seq_term(&seq);
			break;
		}
		strlcpy(rows[nrows].rolename, entry->key.rolename, NAMEDATALEN);
		rows[nrows].pending_failures = entry->pending_failures;
		rows[nrows].lock_pending_audit = entry->lock_pending_audit;
		rows[nrows].failed_count = entry->failed_count;
		rows[nrows].last_failure_at = entry->last_failure_at;
		rows[nrows].locked_until = entry->locked_until;
		nrows++;
	}
	LWLockRelease(ppp_shared->lock);

	for (i = 0; i < nrows; i++)
	{
		pppPendingRow *r = &rows[i];
		int			ret;

		if (r->pending_failures > 0)
		{
			Oid			argtypes[3] = {TEXTOID, INT4OID, TIMESTAMPTZOID};
			Datum		values[3];
			char		nulls[3] = {' ', ' ', ' '};

			values[0] = ppp_text_datum(r->rolename);
			values[1] = Int32GetDatum(r->pending_failures);
			values[2] = TimestampTzGetDatum(r->last_failure_at);
			if (r->last_failure_at == 0)
				nulls[2] = 'n';

			ret = SPI_execute_with_args(
										"SELECT pass_policy.audit('auth_failed', $1, "
										"jsonb_build_object('count', $2, 'last_failure_at', $3, "
										"'source', 'auth_hook'))",
										3, argtypes, values, nulls, false, 0);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "audit('auth_failed') returned SPI code %d", ret);
		}

		if (r->lock_pending_audit && r->locked_until != 0)
		{
			Oid			argtypes[3] = {TEXTOID, TIMESTAMPTZOID, INT4OID};
			Datum		values[3];
			char		nulls[3] = {' ', ' ', ' '};

			values[0] = ppp_text_datum(r->rolename);
			values[1] = TimestampTzGetDatum(r->locked_until);	/* DT_NOEND = infinity */
			values[2] = Int32GetDatum(r->failed_count);

			ret = SPI_execute_with_args(
										"SELECT pass_policy.audit('role_locked', $1, "
										"jsonb_build_object('locked_until', $2, 'failed_count', $3, "
										"'locked_by', 'auto', "
										"'reason', 'too many failed authentication attempts'))",
										3, argtypes, values, nulls, false, 0);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "audit('role_locked') returned SPI code %d", ret);

			/* only existing roles get a role_state row */
			ret = SPI_execute_with_args(
										"INSERT INTO pass_policy.role_state "
										"(role_oid, role_name, locked_until, locked_by, lock_reason) "
										"SELECT r.oid, r.rolname, $2, 'auto', "
										"'too many failed authentication attempts' "
										"FROM pg_catalog.pg_roles r WHERE r.rolname = $1 "
										"ON CONFLICT (role_oid) DO UPDATE SET "
										"role_name = EXCLUDED.role_name, "
										"locked_until = EXCLUDED.locked_until, "
										"locked_by = EXCLUDED.locked_by, "
										"lock_reason = EXCLUDED.lock_reason",
										2, argtypes, values, nulls, false, 0);
			if (ret != SPI_OK_INSERT)
				elog(ERROR, "role_state upsert returned SPI code %d", ret);
		}
	}

	/*
	 * Everything was written: acknowledge what we copied.  Failures counted
	 * by the hook meanwhile stay pending for the next cycle.
	 */
	if (nrows > 0)
	{
		LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
		for (i = 0; i < nrows; i++)
		{
			pppRoleKey	key;

			memset(&key, 0, sizeof(key));
			strlcpy(key.rolename, rows[i].rolename, NAMEDATALEN);
			entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
			if (entry == NULL)
				continue;
			entry->pending_failures -= rows[i].pending_failures;
			if (entry->pending_failures < 0)
				entry->pending_failures = 0;
			if (rows[i].lock_pending_audit &&
				entry->locked_until == rows[i].locked_until)
				entry->lock_pending_audit = false;
		}
		LWLockRelease(ppp_shared->lock);

		elog(DEBUG1, PPP_LOG_PREFIX "synchronised %d shared memory entries", nrows);
	}

	pfree(rows);
}

/* ------------------------------------------------------------------------
 * Step 2b: expired locks and inactive entries (shared memory only)
 * ------------------------------------------------------------------------
 */
static void
ppp_sync_cleanup(void)
{
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	TimestampTz now = GetCurrentTimestamp();
	TimestampTz purge_before = TimestampTzPlusMilliseconds(now,
														   -(int64) PPP_PURGE_AFTER_SECS * 1000);
	int			purged = 0;

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		/* expired lock */
		if (entry->locked_until != 0 && entry->locked_until != DT_NOEND &&
			entry->locked_until <= now && !entry->lock_pending_audit)
		{
			entry->locked_until = 0;
			entry->failed_count = 0;
			entry->first_failure_at = 0;
		}

		/*
		 * Purge inactive entries.  Entries carrying profile parameters are
		 * kept (they are rebuilt on reload anyway).  Removing the current
		 * element during a hash_seq_search scan is allowed.
		 */
		if (!entry->from_profile &&
			entry->locked_until == 0 &&
			!entry->lock_pending_audit &&
			entry->pending_failures <= 0 &&
			entry->last_failure_at < purge_before)
		{
			hash_search(ppp_role_hash, &entry->key, HASH_REMOVE, NULL);
			purged++;
		}
	}
	LWLockRelease(ppp_shared->lock);

	if (purged > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "purged %d inactive shared memory entries", purged);
}

/* ------------------------------------------------------------------------
 * Step 2c: reload profiles and persisted locks
 * ------------------------------------------------------------------------
 */
static int32
ppp_getint(HeapTuple tup, TupleDesc desc, int col, int32 dflt)
{
	bool		isnull;
	Datum		d = SPI_getbinval(tup, desc, col, &isnull);

	return isnull ? dflt : DatumGetInt32(d);
}

static void
ppp_sync_reload(void)
{
	int			ret;
	uint64		i;
	bool		have_default = false;
	int32		def_max = 0,
				def_window = 0,
				def_lock = 0;
	pppProfileRow *profiles = NULL;
	uint64		nprofiles = 0;
	pppLockRow *locks = NULL;
	uint64		nlocks = 0;
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	int			not_tracked = 0;

	/* profile "default" */
	ret = SPI_execute("SELECT p.max_failures, "
					  "extract(epoch FROM p.failure_window)::int4, "
					  "COALESCE(extract(epoch FROM p.lock_duration)::int4, -1) "
					  "FROM pass_policy.profile p WHERE p.name = 'default'",
					  true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "reading profile \"default\" returned SPI code %d", ret);
	if (SPI_processed > 0)
	{
		HeapTuple	tup = SPI_tuptable->vals[0];
		TupleDesc	desc = SPI_tuptable->tupdesc;

		have_default = true;
		def_max = ppp_getint(tup, desc, 1, 0);
		def_window = ppp_getint(tup, desc, 2, 0);
		def_lock = ppp_getint(tup, desc, 3, -1);
	}

	/* roles with an assigned profile; current name taken from pg_roles */
	ret = SPI_execute("SELECT COALESCE(r.rolname::text, rp.role_name), p.max_failures, "
					  "extract(epoch FROM p.failure_window)::int4, "
					  "COALESCE(extract(epoch FROM p.lock_duration)::int4, -1) "
					  "FROM pass_policy.role_profile rp "
					  "JOIN pass_policy.profile p USING (profile_id) "
					  "LEFT JOIN pg_catalog.pg_roles r ON r.oid = rp.role_oid",
					  true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "reading role profiles returned SPI code %d", ret);
	nprofiles = SPI_processed;
	if (nprofiles > 0)
	{
		profiles = (pppProfileRow *) palloc(sizeof(pppProfileRow) * nprofiles);
		for (i = 0; i < nprofiles; i++)
		{
			HeapTuple	tup = SPI_tuptable->vals[i];
			TupleDesc	desc = SPI_tuptable->tupdesc;
			char	   *name = SPI_getvalue(tup, desc, 1);

			memset(profiles[i].rolename, 0, NAMEDATALEN);
			if (name)
				strlcpy(profiles[i].rolename, name, NAMEDATALEN);
			profiles[i].max_failures = ppp_getint(tup, desc, 2, 0);
			profiles[i].failure_window_secs = ppp_getint(tup, desc, 3, 0);
			profiles[i].lock_duration_secs = ppp_getint(tup, desc, 4, -1);
		}
	}

	/* persisted active locks ('infinity' comes back as DT_NOEND) */
	ret = SPI_execute("SELECT COALESCE(r.rolname::text, s.role_name), s.locked_until "
					  "FROM pass_policy.role_state s "
					  "LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.role_oid "
					  "WHERE s.locked_until IS NOT NULL AND s.locked_until > now()",
					  true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "reading role_state returned SPI code %d", ret);
	nlocks = SPI_processed;
	if (nlocks > 0)
	{
		locks = (pppLockRow *) palloc(sizeof(pppLockRow) * nlocks);
		for (i = 0; i < nlocks; i++)
		{
			HeapTuple	tup = SPI_tuptable->vals[i];
			TupleDesc	desc = SPI_tuptable->tupdesc;
			char	   *name = SPI_getvalue(tup, desc, 1);
			bool		isnull;
			Datum		d = SPI_getbinval(tup, desc, 2, &isnull);

			memset(locks[i].rolename, 0, NAMEDATALEN);
			if (name)
				strlcpy(locks[i].rolename, name, NAMEDATALEN);
			locks[i].locked_until = isnull ? 0 : DatumGetTimestampTz(d);
		}
	}

	/* apply everything under the lock; nothing below can fail */
	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);

	if (have_default)
	{
		ppp_shared->default_max_failures = def_max;
		ppp_shared->default_failure_window_secs = def_window;
		ppp_shared->default_lock_duration_secs = def_lock;
	}

	/* every entry falls back to the defaults ... */
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		entry->max_failures = ppp_shared->default_max_failures;
		entry->failure_window_secs = ppp_shared->default_failure_window_secs;
		entry->lock_duration_secs = ppp_shared->default_lock_duration_secs;
		entry->from_profile = false;
	}

	/* ... unless it has an assigned profile */
	for (i = 0; i < nprofiles; i++)
	{
		pppRoleKey	key;
		bool		found;

		if (profiles[i].rolename[0] == '\0')
			continue;
		memset(&key, 0, sizeof(key));
		strlcpy(key.rolename, profiles[i].rolename, NAMEDATALEN);

		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
		if (entry == NULL)
		{
			if (hash_get_num_entries(ppp_role_hash) >= ppp_max_tracked_roles ||
				(entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key,
													  HASH_ENTER_NULL, &found)) == NULL)
			{
				not_tracked++;
				continue;
			}
			entry->failed_count = 0;
			entry->first_failure_at = 0;
			entry->last_failure_at = 0;
			entry->locked_until = 0;
			entry->lock_pending_audit = false;
			entry->pending_failures = 0;
		}
		entry->max_failures = profiles[i].max_failures;
		entry->failure_window_secs = profiles[i].failure_window_secs;
		entry->lock_duration_secs = profiles[i].lock_duration_secs;
		entry->from_profile = true;
	}

	/* persisted locks (after a restart, or set through SQL) */
	for (i = 0; i < nlocks; i++)
	{
		pppRoleKey	key;
		bool		found;

		if (locks[i].rolename[0] == '\0' || locks[i].locked_until == 0)
			continue;
		memset(&key, 0, sizeof(key));
		strlcpy(key.rolename, locks[i].rolename, NAMEDATALEN);

		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
		if (entry == NULL)
		{
			if (hash_get_num_entries(ppp_role_hash) >= ppp_max_tracked_roles ||
				(entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key,
													  HASH_ENTER_NULL, &found)) == NULL)
			{
				not_tracked++;
				continue;
			}
			entry->max_failures = ppp_shared->default_max_failures;
			entry->failure_window_secs = ppp_shared->default_failure_window_secs;
			entry->lock_duration_secs = ppp_shared->default_lock_duration_secs;
			entry->from_profile = false;
			entry->failed_count = 0;
			entry->first_failure_at = 0;
			entry->last_failure_at = 0;
			entry->lock_pending_audit = false;
			entry->pending_failures = 0;
		}
		if (entry->locked_until != locks[i].locked_until)
		{
			entry->locked_until = locks[i].locked_until;
			entry->lock_pending_audit = false;
		}
	}

	ppp_shared->worker_last_reload = GetCurrentTimestamp();

	LWLockRelease(ppp_shared->lock);

	if (not_tracked > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "%d roles could not be loaded in shared memory: too many tracked roles",
						not_tracked),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));

	elog(DEBUG1, PPP_LOG_PREFIX "reloaded lockout parameters: " UINT64_FORMAT " role profiles, " UINT64_FORMAT " locks",
		 nprofiles, nlocks);
}

static void
ppp_step_sync(void)
{
	ppp_sync_pending();
	ppp_sync_cleanup();
	if (ppp_reload_pending)
	{
		ppp_sync_reload();
		ppp_reload_pending = false;
	}
}

/*
 * One cycle.  run_full = false: shared memory synchronisation only
 * (worker_interval = 0).
 */
static void
ppp_worker_cycle(bool run_full)
{
	pgstat_report_activity(STATE_RUNNING, "pg_pass_policy maintenance");

	if (run_full && ppp_enabled)
		(void) ppp_run_in_xact("maintenance", ppp_step_maintenance);

	CHECK_FOR_INTERRUPTS();

	/*
	 * Clear the shared request before reading the tables, so that a request
	 * made while we read is not lost.  run_maintenance() calls
	 * shmem_reload(), so this happens every cycle.  ppp_reload_pending is
	 * only cleared once the reload has been done (see ppp_step_sync).
	 */
	if (pg_atomic_exchange_u32(&ppp_shared->reload_requested, 0) != 0)
		ppp_reload_pending = true;

	(void) ppp_run_in_xact("shared memory synchronisation", ppp_step_sync);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	ppp_shared->worker_last_run = GetCurrentTimestamp();
	LWLockRelease(ppp_shared->lock);

	pgstat_report_activity(STATE_IDLE, NULL);
}

/*
 * Worker entry point.
 */
PGDLLEXPORT void
ppp_worker_main(Datum main_arg)
{
	bool		run_now = true;

	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	if (ppp_shared == NULL || ppp_role_hash == NULL)
		ereport(FATAL,
				(errmsg(PPP_LOG_PREFIX "shared memory is not initialized")));

	BackgroundWorkerInitializeConnection(ppp_database, NULL, 0);

	ppp_worker_cxt = AllocSetContextCreate(TopMemoryContext,
										   "pg_pass_policy worker",
										   ALLOCSET_DEFAULT_SIZES);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	ppp_shared->worker_pid = MyProcPid;
	LWLockRelease(ppp_shared->lock);
	on_shmem_exit(ppp_worker_on_exit, (Datum) 0);

	ereport(LOG,
			(errmsg(PPP_LOG_PREFIX "worker started on database \"%s\"",
					ppp_database)));

	for (;;)
	{
		long		timeout;
		int			events;
		int			rc;

		CHECK_FOR_INTERRUPTS();

		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
			run_now = true;
		}

		if (pg_atomic_read_u32(&ppp_shared->reload_requested) != 0)
			run_now = true;

		if (run_now && !RecoveryInProgress())
		{
			MemoryContext oldcxt = MemoryContextSwitchTo(ppp_worker_cxt);

			ppp_worker_cycle(ppp_worker_interval > 0);
			MemoryContextSwitchTo(oldcxt);
			MemoryContextReset(ppp_worker_cxt);
		}
		run_now = false;

		/*
		 * interval = 0: sleep until signalled.  On a standby, poll every
		 * minute for promotion.
		 */
		events = WL_LATCH_SET | WL_EXIT_ON_PM_DEATH;
		if (RecoveryInProgress())
			timeout = 60 * 1000L;
		else if (ppp_worker_interval > 0)
			timeout = ppp_worker_interval * 1000L;
		else
			timeout = -1;
		if (timeout >= 0)
			events |= WL_TIMEOUT;

		rc = WaitLatch(MyLatch, events, timeout, PG_WAIT_EXTENSION);
		ResetLatch(MyLatch);

		if (rc & WL_TIMEOUT)
			run_now = true;
	}
}
