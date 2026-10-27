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
 *	 2. pending audit (own transaction): audit rows for pending failures /
 *		locks, locks copied to role_state.  The shared memory counters are
 *		acknowledged only after this transaction has committed, so that a
 *		failure (or an error in a later step) never loses an audit row or
 *		a persisted lock.
 *	 3. shared memory synchronisation (own transaction):
 *		a. expired locks cleared, inactive entries purged, entries of
 *		   non-existent roles flagged (and purged after their failure
 *		   window);
 *		b. when requested (shmem_reload() or first cycle): persisted locks
 *		   re-injected from role_state, lockout parameters reloaded from the
 *		   profiles.
 *
 * On a hot standby (RecoveryInProgress()), a read-only cycle runs instead
 * (ppp_worker_cycle_standby): steps 1 and 2 write and are skipped, step 3
 * only issues SELECTs and runs at every cycle with a forced reload, since
 * nothing can signal the standby's worker when role_state or the profiles
 * change on the primary.  See SPEC 6.4.
 *
 * The worker connects as superuser: every SQL it runs is schema-qualified
 * and search_path is pinned to pg_catalog, pg_temp.
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
#include "utils/array.h"
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
 * Copies of the shared memory entries written to the tables by the current
 * cycle (allocated in ppp_worker_cxt so that they survive SPI_finish and the
 * end of the transaction).  They are acknowledged in shared memory by
 * ppp_ack_pending() once the transaction that wrote them has committed.
 */
static pppPendingRow *ppp_pending_rows = NULL;
static int	ppp_pending_nrows = 0;


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
	/* also started on a hot standby: locks must be enforced there too */
	worker.bgw_start_time = BgWorkerStart_ConsistentState;
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

		if (ppp_extension_installed())
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
 * Step 2: pending audit rows and locks -> tables
 *
 * Runs inside its own transaction (ppp_run_in_xact).  The rows copied here
 * are kept in ppp_pending_rows; nothing is modified in shared memory until
 * ppp_ack_pending() is called after the commit.
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

	Assert(ppp_pending_rows == NULL);
	rows = (pppPendingRow *) MemoryContextAlloc(ppp_worker_cxt,
												sizeof(pppPendingRow) * maxrows);
	ppp_pending_rows = rows;

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
	ppp_pending_nrows = nrows;

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
										"pg_catalog.jsonb_build_object('count', $2, 'last_failure_at', $3, "
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
										"pg_catalog.jsonb_build_object('locked_until', $2, 'failed_count', $3, "
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

	if (nrows > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "wrote %d pending shared memory entries", nrows);
}

/*
 * Acknowledge in shared memory what ppp_sync_pending() wrote, once its
 * transaction has committed.  Failures counted by the hook meanwhile stay
 * pending for the next cycle; a lock set again since (different
 * locked_until) keeps its pending flag.
 */
static void
ppp_ack_pending(void)
{
	int			i;

	if (ppp_pending_nrows <= 0)
		return;

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (i = 0; i < ppp_pending_nrows; i++)
	{
		pppPendingRow *r = &ppp_pending_rows[i];
		pppRoleKey	key;
		pppRoleEntry *entry;

		memset(&key, 0, sizeof(key));
		strlcpy(key.rolename, r->rolename, NAMEDATALEN);
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
		if (entry == NULL)
			continue;
		entry->pending_failures -= r->pending_failures;
		if (entry->pending_failures < 0)
			entry->pending_failures = 0;
		if (r->lock_pending_audit && entry->locked_until == r->locked_until)
			entry->lock_pending_audit = false;
	}
	LWLockRelease(ppp_shared->lock);

	elog(DEBUG1, PPP_LOG_PREFIX "synchronised %d shared memory entries",
		 ppp_pending_nrows);
}

/* Free the copies, acknowledged or not. */
static void
ppp_free_pending(void)
{
	if (ppp_pending_rows != NULL)
		pfree(ppp_pending_rows);
	ppp_pending_rows = NULL;
	ppp_pending_nrows = 0;
}

/* ------------------------------------------------------------------------
 * Step 3a: expired locks and inactive entries (shared memory only)
 * ------------------------------------------------------------------------
 */
/*
 * Can an entry be purged (or its role checked for existence)?  Same rule as
 * the eviction of ppp_enter_role(): no profile parameters, no lock, nothing
 * left to audit.  Caller holds ppp_shared->lock.
 */
static inline bool
ppp_entry_inactive(const pppRoleEntry *entry)
{
	return !entry->from_profile &&
		entry->locked_until == 0 &&
		!entry->lock_pending_audit &&
		entry->pending_failures <= 0;
}

static void
ppp_sync_cleanup(void)
{
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	TimestampTz now = GetCurrentTimestamp();
	TimestampTz purge_before = TimestampTzPlusMilliseconds(now,
														   -(int64) PPP_PURGE_AFTER_SECS * 1000);
	int			purged = 0;
	int			purged_missing = 0;
	int			maxnames = ppp_max_tracked_roles > 0 ? ppp_max_tracked_roles : 1;
	char	  (*names)[NAMEDATALEN];
	Datum	   *datums;
	int			nnames = 0;
	bool	   *exists;
	int			i;

	names = palloc(sizeof(*names) * maxnames);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		/*
		 * Expired lock (once its role_locked audit row has been written).
		 * The authentication hook may already have counted new failures
		 * after the expiry while locked_until was still set: those belong to
		 * a new episode (first_failure_at >= locked_until) and are kept.
		 */
		if (entry->locked_until != 0 && entry->locked_until != DT_NOEND &&
			entry->locked_until <= now && !entry->lock_pending_audit)
		{
			if (entry->first_failure_at < entry->locked_until)
			{
				entry->failed_count = 0;
				entry->first_failure_at = 0;
			}
			entry->locked_until = 0;
			entry->lock_from_state = false;
		}

		if (!ppp_entry_inactive(entry))
			continue;

		/*
		 * Purge inactive entries.  Entries carrying profile parameters are
		 * kept (they are rebuilt on reload anyway).  Removing the current
		 * element during a hash_seq_search scan is allowed.
		 */
		if (entry->last_failure_at < purge_before)
		{
			hash_search(ppp_role_hash, &entry->key, HASH_REMOVE, NULL);
			purged++;
			continue;
		}

		/* the others are checked against pg_authid below */
		if (nnames < maxnames)
			strlcpy(names[nnames++], entry->key.rolename, NAMEDATALEN);
	}
	LWLockRelease(ppp_shared->lock);

	if (nnames == 0)
		goto done;

	/*
	 * The authentication hook creates an entry for any user name a client
	 * sends, existing or not (it has no catalog access).  Flag the entries
	 * of non-existent roles: the hook evicts them first when the hash is
	 * full (ppp_enter_role), and they are purged once their failure window
	 * has elapsed instead of after 24 h.  Read-only: also runs on a standby.
	 */
	datums = palloc(sizeof(Datum) * nnames);
	for (i = 0; i < nnames; i++)
		datums[i] = CStringGetTextDatum(names[i]);
	{
		ArrayType  *arr = construct_array(datums, nnames, TEXTOID, -1, false,
										  TYPALIGN_INT);
		Oid			argtypes[1] = {TEXTARRAYOID};
		Datum		values[1];
		int			ret;

		values[0] = PointerGetDatum(arr);
		ret = SPI_execute_with_args("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r "
									"WHERE r.rolname = u.n::pg_catalog.name) "
									"FROM pg_catalog.unnest($1) WITH ORDINALITY AS u(n, i) "
									"ORDER BY u.i",
									1, argtypes, values, NULL, true, 0);
		if (ret != SPI_OK_SELECT || SPI_processed != (uint64) nnames)
			elog(ERROR, "checking role existence returned SPI code %d", ret);
	}
	exists = palloc(sizeof(bool) * nnames);
	for (i = 0; i < nnames; i++)
	{
		bool		isnull;
		Datum		d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc,
									  1, &isnull);

		exists[i] = isnull ? true : DatumGetBool(d);
	}

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (i = 0; i < nnames; i++)
	{
		pppRoleKey	key;
		int64		window_secs;

		memset(&key, 0, sizeof(key));
		strlcpy(key.rolename, names[i], NAMEDATALEN);
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
		if (entry == NULL)
			continue;
		entry->role_missing = !exists[i];
		if (exists[i] || !ppp_entry_inactive(entry))
			continue;

		window_secs = entry->failure_window_secs > 0 ?
			entry->failure_window_secs : PPP_PURGE_AFTER_SECS;
		if (entry->last_failure_at <
			TimestampTzPlusMilliseconds(now, -window_secs * 1000))
		{
			hash_search(ppp_role_hash, &entry->key, HASH_REMOVE, NULL);
			purged_missing++;
		}
	}
	LWLockRelease(ppp_shared->lock);

done:
	if (purged > 0 || purged_missing > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "purged %d inactive shared memory entries and %d entries of non-existent roles",
			 purged, purged_missing);
}

/* ------------------------------------------------------------------------
 * Step 3b: reload profiles and persisted locks
 * ------------------------------------------------------------------------
 */
static int32
ppp_getint(HeapTuple tup, TupleDesc desc, int col, int32 dflt)
{
	bool		isnull;
	Datum		d = SPI_getbinval(tup, desc, col, &isnull);

	return isnull ? dflt : DatumGetInt32(d);
}

/* add an eviction made by ppp_enter_role() to the totals of a reload */
static void
ppp_count_eviction(const pppEviction *ev, int *n_evicted, int *lost_failed,
				   int *lost_pending)
{
	if (!ev->evicted)
		return;
	(*n_evicted)++;
	*lost_failed += ev->lost_failed_count;
	*lost_pending += ev->lost_pending_failures;
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
	int			n_evicted = 0;
	int			lost_failed = 0;
	int			lost_pending = 0;
	int			n_lifted = 0;
	TimestampTz now;
	bool		in_recovery;

	/*
	 * Durations are clamped to INT_MAX seconds (about 68 years) before the
	 * int4 cast: a longer (legal) interval, or 'infinity', would otherwise
	 * raise "integer out of range" at every cycle.  COALESCE comes first so
	 * that NULL (manual unlock only) stays -1.
	 */
	/* profile "default" */
	ret = SPI_execute("SELECT p.max_failures, "
					  "LEAST(extract(epoch FROM p.failure_window), 2147483647)::int4, "
					  "LEAST(COALESCE(extract(epoch FROM p.lock_duration), -1), 2147483647)::int4 "
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
					  "LEAST(extract(epoch FROM p.failure_window), 2147483647)::int4, "
					  "LEAST(COALESCE(extract(epoch FROM p.lock_duration), -1), 2147483647)::int4 "
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

	/*
	 * Apply everything under the lock; nothing below can fail.
	 *
	 * Persisted locks are injected before the profile entries, and both use
	 * PPP_ENTER_PRIORITY: when the hash is full they evict plain counting
	 * entries (ppp_enter_role) rather than being dropped, and a profile
	 * entry can never take the room of a lock.  The from_profile flag of
	 * the previous reload is only cleared at the end (reload_profile_seen),
	 * so that an entry whose profile is still assigned cannot be evicted
	 * by the insertions of this very reload.
	 */
	now = GetCurrentTimestamp();
	in_recovery = RecoveryInProgress();

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);

	if (have_default)
	{
		ppp_shared->default_max_failures = def_max;
		ppp_shared->default_failure_window_secs = def_window;
		ppp_shared->default_lock_duration_secs = def_lock;
	}

	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		entry->reload_profile_seen = false;
		entry->reload_lock_seen = false;
	}

	/* persisted locks (after a restart, set through SQL, or replicated) */
	for (i = 0; i < nlocks; i++)
	{
		pppEviction ev;

		if (locks[i].rolename[0] == '\0' || locks[i].locked_until == 0)
			continue;

		entry = ppp_enter_role(locks[i].rolename, PPP_ENTER_PRIORITY, now, &ev);
		ppp_count_eviction(&ev, &n_evicted, &lost_failed, &lost_pending);
		if (entry == NULL)
		{
			not_tracked++;
			continue;
		}
		if (entry->locked_until != locks[i].locked_until)
		{
			entry->locked_until = locks[i].locked_until;
			entry->lock_pending_audit = false;
		}
		entry->lock_from_state = true;
		entry->reload_lock_seen = true;
	}

	/* roles with an assigned profile */
	for (i = 0; i < nprofiles; i++)
	{
		pppEviction ev;

		if (profiles[i].rolename[0] == '\0')
			continue;

		entry = ppp_enter_role(profiles[i].rolename, PPP_ENTER_PRIORITY, now, &ev);
		ppp_count_eviction(&ev, &n_evicted, &lost_failed, &lost_pending);
		if (entry == NULL)
		{
			not_tracked++;
			continue;
		}
		entry->max_failures = profiles[i].max_failures;
		entry->failure_window_secs = profiles[i].failure_window_secs;
		entry->lock_duration_secs = profiles[i].lock_duration_secs;
		entry->from_profile = true;
		entry->reload_profile_seen = true;
	}

	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		/* every other entry falls back to the defaults */
		if (!entry->reload_profile_seen)
		{
			entry->max_failures = ppp_shared->default_max_failures;
			entry->failure_window_secs = ppp_shared->default_failure_window_secs;
			entry->lock_duration_secs = ppp_shared->default_lock_duration_secs;
			entry->from_profile = false;
		}

		/*
		 * On a standby, a lock re-injected from role_state that is no
		 * longer there has been lifted on the primary (unlock_role(),
		 * expiry): nobody else can clear it here.  Locks set locally (by
		 * the authentication hook, or shmem_lock_role()) are left alone.
		 * Not done on a primary: it would race with a lock_role()
		 * committed after our snapshot was taken (SPEC 11).
		 */
		if (in_recovery && entry->lock_from_state && !entry->reload_lock_seen)
		{
			entry->locked_until = 0;
			entry->lock_pending_audit = false;
			entry->lock_from_state = false;
			n_lifted++;
		}
	}

	ppp_shared->worker_last_reload = GetCurrentTimestamp();

	LWLockRelease(ppp_shared->lock);

	if (not_tracked > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "%d roles could not be loaded in shared memory: too many tracked roles",
						not_tracked),
				 errdetail("Every entry holds a lock or profile parameters."),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));
	if (lost_failed > 0 || lost_pending > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "shared memory full: %d entries evicted to load locks and profiles (%d counted failures, %d failures not yet audited lost)",
						n_evicted, lost_failed, lost_pending),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));
	else if (n_evicted > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "shared memory full: %d inactive entries evicted to load locks and profiles",
			 n_evicted);
	if (n_lifted > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "%d locks lifted on the primary removed from shared memory",
			 n_lifted);

	elog(DEBUG1, PPP_LOG_PREFIX "reloaded lockout parameters: " UINT64_FORMAT " role profiles, " UINT64_FORMAT " locks",
		 nprofiles, nlocks);
}

static void
ppp_step_sync(void)
{
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

	/*
	 * Pending audit rows and locks, in their own transaction: the shared
	 * memory is acknowledged only once they are committed, and an error in
	 * the synchronisation step below cannot roll them back.
	 */
	if (ppp_run_in_xact("pending audit", ppp_sync_pending))
		ppp_ack_pending();
	ppp_free_pending();

	CHECK_FOR_INTERRUPTS();

	(void) ppp_run_in_xact("shared memory synchronisation", ppp_step_sync);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	ppp_shared->worker_last_run = GetCurrentTimestamp();
	LWLockRelease(ppp_shared->lock);

	pgstat_report_activity(STATE_IDLE, NULL);
}

/*
 * A standby cannot write audit_log or role_state: the failures and locks
 * counted there by the authentication hook are logged and acknowledged,
 * otherwise their entries could never be evicted nor their expired locks
 * cleared (ppp_sync_cleanup only clears audited locks).  The server log
 * already holds the details (authentication failures, "role locked after"
 * messages of the hook).
 */
static void
ppp_standby_ack_pending(void)
{
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	int			failures = 0;
	int			locks = 0;

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		if (entry->pending_failures > 0)
		{
			failures += entry->pending_failures;
			entry->pending_failures = 0;
		}
		if (entry->lock_pending_audit)
		{
			locks++;
			entry->lock_pending_audit = false;
		}
	}
	LWLockRelease(ppp_shared->lock);

	if (failures > 0 || locks > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "%d authentication failures and %d locks counted on this standby are not written to the audit log (server is in recovery)",
						failures, locks)));
}

/*
 * Read-only cycle of a hot standby.
 *
 * run_maintenance() and the pending audit step write and cannot run.  The
 * shared memory hash must still be filled from the replicated role_state
 * and profiles, otherwise a role locked on the primary could log in on the
 * standby.  shmem_reload() cannot reach this worker (it runs on the
 * primary), so the reload is forced at every cycle: three SELECTs per
 * pg_pass_policy.worker_interval, simpler and more robust than detecting
 * changes.  The transactions are read-only (StartTransaction forces
 * XactReadOnly during recovery); ppp_sync_cleanup and ppp_sync_reload only
 * issue SELECTs, without pg_notify nor any function that writes.
 */
static void
ppp_worker_cycle_standby(void)
{
	pgstat_report_activity(STATE_RUNNING, "pg_pass_policy standby synchronisation");

	(void) pg_atomic_exchange_u32(&ppp_shared->reload_requested, 0);
	ppp_reload_pending = true;

	ppp_standby_ack_pending();

	(void) ppp_run_in_xact("standby synchronisation", ppp_step_sync);

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
	bool		was_in_recovery = false;

	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	if (ppp_shared == NULL || ppp_role_hash == NULL)
		ereport(FATAL,
				(errmsg(PPP_LOG_PREFIX "shared memory is not initialized")));

	BackgroundWorkerInitializeConnection(ppp_database, NULL, 0);

	/*
	 * Defence in depth: the worker runs as superuser and every query it
	 * issues is schema-qualified, but a safe search_path makes sure that no
	 * object created in a user schema (public) can ever be picked up.
	 */
	SetConfigOption("search_path", "pg_catalog, pg_temp", PGC_SUSET, PGC_S_SESSION);

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

		if (run_now)
		{
			MemoryContext oldcxt = MemoryContextSwitchTo(ppp_worker_cxt);

			if (RecoveryInProgress())
			{
				ppp_worker_cycle_standby();
				was_in_recovery = true;
			}
			else
			{
				/* just promoted: reload everything once */
				if (was_in_recovery)
				{
					ppp_reload_pending = true;
					was_in_recovery = false;
				}
				ppp_worker_cycle(ppp_worker_interval > 0);
			}
			MemoryContextSwitchTo(oldcxt);
			MemoryContextReset(ppp_worker_cxt);
		}
		run_now = false;

		/*
		 * interval = 0: sleep until signalled.  On a standby nothing signals
		 * the changes replicated from the primary: always poll, every
		 * worker_interval (60 s when it is 0), which also detects promotion.
		 */
		events = WL_LATCH_SET | WL_EXIT_ON_PM_DEATH;
		if (RecoveryInProgress())
			timeout = (ppp_worker_interval > 0 ? ppp_worker_interval : 60) * 1000L;
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
