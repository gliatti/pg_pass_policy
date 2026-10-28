/*-------------------------------------------------------------------------
 *
 * worker.c
 *		pg_pass_policy background worker: periodic maintenance and
 *		synchronisation between the shared memory hash (lockout.c) and the
 *		pg_pass_policy tables.
 *
 * Each cycle, in pg_pass_policy.database:
 *	 0. first cycle after start-up, promotion or enabled turned on again
 *		only: step 3 with a forced reload, before anything else, so that the
 *		persisted locks are re-injected before run_maintenance() (which may
 *		wait for pg_cron's pass) and the pending audit (ppp_sync_first);
 *	 1. SELECT * FROM pass_policy.run_maintenance()  (own transaction;
 *		skipped when pg_pass_policy.worker_interval = 0)
 *	 2. pending audit (own transaction): audit rows for pending failures /
 *		locks, locks copied to role_state.  The shared memory counters are
 *		acknowledged only after this transaction has committed, so that a
 *		failure (or an error in a later step) never loses an audit row or
 *		a persisted lock.
 *	 3. shared memory synchronisation (own transaction):
 *		a. entries of dropped roles removed (or flagged role_dropped while
 *		   their audit is pending), expired locks cleared, inactive entries
 *		   purged, pseudo-entries (user names without role) purged after
 *		   their failure window;
 *		b. when requested (shmem_reload(), or step 0): persisted locks
 *		   re-injected from role_state (locks mirrored there but no longer
 *		   in it are lifted), lockout parameters reloaded from the profiles.
 *
 * With pg_pass_policy.enabled = off, the cycle is suspended altogether
 * (ppp_worker_suspended): no maintenance, no audit row, no role_state
 * write, no shared memory clean-up nor reload.  The failures and locks
 * pending in shared memory stay pending, and a reload request is kept, until
 * the extension is enabled again; the first cycle after that does all of
 * it, with a forced reload.
 *
 * On a hot standby (RecoveryInProgress()), a read-only cycle runs instead
 * (ppp_worker_cycle_standby): steps 1 and 2 write and are skipped (the
 * failures and locks counted locally stay pending and are audited by the
 * first cycle after promotion), step 3 only issues SELECTs and runs at every
 * cycle with a forced reload, since nothing can signal the standby's worker
 * when role_state or the profiles change on the primary.  See SPEC 6.4.
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
#include "catalog/pg_authid.h"
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
#include "utils/syscache.h"
#include "utils/timestamp.h"

#include "pg_pass_policy.h"
#include "compat.h"

/* inactive entries without lock are purged after this delay */
#define PPP_PURGE_AFTER_SECS	(24 * 60 * 60)

/*
 * Delay before a new attempt while a reload is pending or the fail-closed
 * start-up window is still open (SPEC 6.3), whatever worker_interval.
 */
#define PPP_RETRY_SECS			5

/* at most one message per minute for the conditions that last */
#define PPP_UNTRUSTED_LOG_SECS	60
#define PPP_WINDOW_KEPT_LOG_SECS 60
/* at most one message per hour for the restored rows not bound yet */
#define PPP_UNBOUND_LOG_SECS	3600

/*
 * Profile durations converted to whole seconds for the shared memory (see
 * ppp_sync_reload): clamped to [1, INT_MAX], 0 = no window, -1 = manual
 * unlock only.  GREATEST() ignores NULLs, hence the explicit CASE.
 */
#define PPP_SQL_WINDOW_SECS \
	"(CASE WHEN p.failure_window > interval '0' " \
	"THEN GREATEST(LEAST(extract(epoch FROM p.failure_window), 2147483647), 1) " \
	"ELSE 0 END)::int4"
#define PPP_SQL_LOCK_SECS \
	"(CASE WHEN p.lock_duration IS NULL THEN -1 " \
	"ELSE GREATEST(LEAST(extract(epoch FROM p.lock_duration), 2147483647), 1) " \
	"END)::int4"

/* copy of an entry with something to write to the tables */
typedef struct pppPendingRow
{
	pppRoleKey	key;
	char		rolename[NAMEDATALEN];	/* last known name (entry->rolename) */
	int32		pending_failures;
	bool		lock_pending_audit;
	int32		failed_count;
	TimestampTz last_failure_at;
	TimestampTz locked_until;
	TimestampTz audit_locked_until; /* lock to audit (lock_pending_audit) */
	uint32		audit_lock_seq; /* its episode number */
	TimestampTz audit_lock_set_at;	/* when that lock was set */
	uint32		lost_episodes;	/* earlier episodes overwritten unaudited */
	uint64		lock_seq;		/* entry->lock_seq when copied */
	uint64		generation;		/* entry->generation when copied */
	bool		state_written;	/* role_state upserted with locked_until */
} pppPendingRow;

/* lockout parameters of an existing role, read from the profiles */
typedef struct pppProfileRow
{
	Oid			roleid;
	char		rolename[NAMEDATALEN];
	int32		max_failures;
	int32		failure_window_secs;
	int32		lock_duration_secs;
} pppProfileRow;

/* persisted lock read from role_state */
typedef struct pppLockRow
{
	Oid			roleid;
	char		rolename[NAMEDATALEN];
	TimestampTz locked_until;
} pppLockRow;

static MemoryContext ppp_worker_cxt = NULL;

/*
 * A reload was requested and has not been carried out yet (error, or
 * persisted locks that did not all fit in shared memory).  Kept locally
 * instead of re-setting ppp_shared->reload_requested, which would make the
 * main loop run again immediately, in a busy loop.  Retried on the next
 * timed cycle, at most PPP_RETRY_SECS later even with worker_interval = 0
 * (see ppp_worker_main).  Cleared when the extension is not installed:
 * nothing to reload.
 */
static bool ppp_reload_pending = false;

/*
 * The next primary cycle must synchronise the shared memory (clean-up and
 * forced reload) BEFORE run_maintenance() and the pending audit step: set at
 * start-up, after promotion and when pg_pass_policy.enabled is turned on
 * again.  Until the persisted locks are re-injected from role_state, a
 * locked role is not known to the authentication hook; run_maintenance() may
 * take long (full pass, wait for the advisory lock held by pg_cron), and the
 * session of a role that gets in meanwhile survives the reload.  Cleared once
 * that reload has succeeded (SPEC 6.4).
 */
static bool ppp_sync_first = true;

/* rate limiters of the worker's own messages (this process only) */
static TimestampTz ppp_untrusted_logged_at = 0;
static TimestampTz ppp_window_kept_logged_at = 0;
static TimestampTz ppp_unbound_logged_at = 0;

/* end of the last complete primary cycle (ppp_worker_cycle), 0 = none yet */
static TimestampTz ppp_full_cycle_at = 0;

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
 * on_shmem_exit callback: unpublish our PID, unless a newer worker has
 * already published its own (compare-and-exchange, no LWLock: see
 * pppSharedState.worker_pid).
 */
static void
ppp_worker_on_exit(int code, Datum arg)
{
	uint32		expected = (uint32) MyProcPid;

	if (ppp_shared != NULL)
		(void) pg_atomic_compare_exchange_u32(&ppp_shared->worker_pid,
											  &expected, 0);
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
		pppExtensionState ext_state;
		Oid			nspowner;

		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");
		PushActiveSnapshot(GetTransactionSnapshot());

		ext_state = ppp_extension_state(&nspowner);
		if (ext_state == PPP_EXT_TRUSTED)
			step();
		else if (ext_state == PPP_EXT_UNTRUSTED)
		{
			/*
			 * Installed but untrusted: the worker does nothing, and the
			 * start-up window, if still open, stays closed.  This is a
			 * misconfiguration that keeps connections refused: say so in
			 * the log, at most once per minute (every cycle step comes
			 * here).
			 */
			if (ppp_log_due(&ppp_untrusted_logged_at, GetCurrentTimestamp(),
							PPP_UNTRUSTED_LOG_SECS * 1000))
				ereport(WARNING,
						(errmsg(PPP_LOG_PREFIX "extension in database \"%s\" is not trusted, the worker does nothing",
								ppp_database),
						 errdetail_internal("%s", ppp_untrusted_detail(nspowner)),
						 errhint("A superuser must own schema \"" PPP_SCHEMA "\" (ALTER SCHEMA " PPP_SCHEMA " OWNER TO a superuser).  Until the lock state is loaded, roles authenticating with a password or a secret are refused (at most one message per minute).")));
		}
		else
		{
			elog(DEBUG1, PPP_LOG_PREFIX "extension not installed in database \"%s\", nothing to do",
				 ppp_database);

			/*
			 * No extension, no persisted lock to re-inject: the start-up
			 * window of the authentication hook can be closed (otherwise
			 * every non-exempt role would be refused until CREATE
			 * EXTENSION), and there is nothing to reload: the pending
			 * request and the "synchronise first" step are dropped, so that
			 * the following cycles do not run them again, in an extra
			 * transaction, until the extension is created (run_maintenance()
			 * then requests a reload).  An installed but untrusted extension
			 * keeps the window closed: role_state exists but cannot be read
			 * safely.
			 */
			ppp_reload_pending = false;
			ppp_sync_first = false;
			if (!ppp_shared->locks_loaded)
			{
				LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
				ppp_shared->locks_loaded = true;
				LWLockRelease(ppp_shared->lock);
			}
		}

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
	int			maxrows;
	int			i;
	int			ghost_names = 0;
	int64		ghost_attempts = 0;
	int			ghost_locks = 0;
	TimestampTz ghost_last = 0;

	Assert(ppp_pending_rows == NULL);
	/* read only: a shared lock is enough (the acknowledgement is separate) */
	rows = (pppPendingRow *) ppp_alloc_hash_copy(ppp_worker_cxt,
												 sizeof(pppPendingRow),
												 &maxrows, LW_SHARED);
	ppp_pending_rows = rows;

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
		memcpy(&rows[nrows].key, &entry->key, sizeof(pppRoleKey));
		strlcpy(rows[nrows].rolename, entry->rolename, NAMEDATALEN);
		rows[nrows].pending_failures = entry->pending_failures;
		rows[nrows].lock_pending_audit = entry->lock_pending_audit;
		rows[nrows].failed_count = entry->failed_count;
		rows[nrows].last_failure_at = entry->last_failure_at;
		rows[nrows].locked_until = entry->locked_until;
		rows[nrows].audit_locked_until = entry->audit_locked_until;
		rows[nrows].audit_lock_seq = entry->audit_lock_seq;
		rows[nrows].audit_lock_set_at = entry->audit_lock_set_at;
		rows[nrows].lost_episodes = 0;

		/*
		 * Signed difference, bounded at 0: audit_acked_seq is never ahead
		 * of audit_lock_seq (ppp_ack_pending), but an unsigned difference
		 * would turn any inconsistency into some four billion lost
		 * episodes.
		 */
		if (entry->lock_pending_audit &&
			(int32) (entry->audit_lock_seq - entry->audit_acked_seq) > 1)
			rows[nrows].lost_episodes = entry->audit_lock_seq -
				entry->audit_acked_seq - 1;
		rows[nrows].lock_seq = entry->lock_seq;
		rows[nrows].generation = entry->generation;
		rows[nrows].state_written = false;
		nrows++;
	}
	LWLockRelease(ppp_shared->lock);
	ppp_pending_nrows = nrows;

	for (i = 0; i < nrows; i++)
	{
		pppPendingRow *r = &rows[i];
		int			ret;
		bool		lock_to_audit;
		bool		still_locked;
		bool		replaced;
		bool		dropped;
		char	   *name;

		/*
		 * Pseudo-entries (user names without role): one aggregated
		 * auth_failed row per cycle (below) instead of one row, and one
		 * NOTIFY, per invented name.  Their pseudo-locks are counted there
		 * too: role_state has no row for them.  They are acknowledged like
		 * the others.
		 */
		if (!OidIsValid(r->key.roleid))
		{
			ghost_names++;
			ghost_attempts += Max(r->pending_failures, 0);
			if (r->lock_pending_audit && r->audit_locked_until != 0)
				ghost_locks += 1 + r->lost_episodes;
			if (r->last_failure_at > ghost_last)
				ghost_last = r->last_failure_at;
			continue;
		}

		/*
		 * The lock was lifted (unlock_role(): locked_until cleared,
		 * lifted_before_audit) or replaced (lock_role(), or a lock
		 * re-injected from role_state: another locked_until,
		 * replaced_by_manual) before this cycle.  It is audited all the
		 * same, but role_state must not be locked again with it.  The
		 * replacement is told by locked_until itself, not by whether it is
		 * still active: a manual lock that has expired since is kept in the
		 * entry while the automatic one waits for its audit
		 * (ppp_expire_lock), and is still a replacement.  Another automatic
		 * lock would have overwritten audit_locked_until as well
		 * (lost_episodes).
		 */
		lock_to_audit = r->lock_pending_audit && r->audit_locked_until != 0;
		still_locked = (r->locked_until == r->audit_locked_until);
		replaced = !still_locked && r->locked_until != 0;

		if (lock_to_audit && still_locked)
		{
			Oid			argtypes[2] = {OIDOID, TIMESTAMPTZOID};
			Datum		values[2];

			/*
			 * Copy the lock to the role_state row of the OID, first: the
			 * audit row follows from the result, without any lookup that
			 * could race with the write.  Its name is the current name of
			 * the role (role_state has none for a dropped OID: no row
			 * written, role_dropped).  Row of this cluster only (cluster_id
			 * default): a restored row of the same OID is another, inert
			 * row, never touched here (SPEC 6.3).
			 */
			values[0] = ObjectIdGetDatum(r->key.roleid);
			values[1] = TimestampTzGetDatum(r->audit_locked_until); /* DT_NOEND = infinity */
			ret = SPI_execute_with_args(
										"WITH r AS (SELECT a.oid, a.rolname FROM pg_catalog.pg_authid a "
										"WHERE a.oid = $1), "
										"u AS (INSERT INTO pass_policy.role_state AS s "
										"(role_oid, role_name, locked_until, locked_by, lock_reason) "
										"SELECT r.oid, r.rolname, $2, 'auto', "
										"'too many failed authentication attempts' FROM r "
										"ON CONFLICT (role_oid, cluster_id) DO UPDATE SET "
										"role_name = EXCLUDED.role_name, "
										"locked_until = EXCLUDED.locked_until, "
										"locked_by = EXCLUDED.locked_by, "
										"lock_reason = EXCLUDED.lock_reason) "
										"SELECT (SELECT r.rolname::pg_catalog.text FROM r)",
										2, argtypes, values, NULL, false, 1);
			if (ret != SPI_OK_SELECT || SPI_processed != 1)
				elog(ERROR, "role_state upsert of OID %u returned SPI code %d",
					 r->key.roleid, ret);
			name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
			dropped = (name == NULL);
			r->state_written = !dropped;
		}
		else
		{
			Oid			argtypes[1] = {OIDOID};
			Datum		values[1];

			/* current name of the role, NULL once dropped */
			values[0] = ObjectIdGetDatum(r->key.roleid);
			ret = SPI_execute_with_args(
										"SELECT a.rolname::pg_catalog.text FROM pg_catalog.pg_authid a "
										"WHERE a.oid = $1",
										1, argtypes, values, NULL, true, 1);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "role lookup of OID %u returned SPI code %d",
					 r->key.roleid, ret);
			name = SPI_processed > 0 ?
				SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1) :
				NULL;
			dropped = (name == NULL);
		}
		/* a dropped role is audited under the last name the entry knew */
		if (name == NULL)
			name = r->rolename;

		if (r->pending_failures > 0)
		{
			Oid			argtypes[3] = {TEXTOID, INT4OID, TIMESTAMPTZOID};
			Datum		values[3];
			char		nulls[3] = {' ', ' ', ' '};

			values[0] = CStringGetTextDatum(name);
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

		if (lock_to_audit)
		{
			Oid			argtypes[8] = {TEXTOID, TIMESTAMPTZOID, INT4OID, BOOLOID,
				INT8OID, BOOLOID, BOOLOID, OIDOID};
			Datum		values[8];

			values[0] = CStringGetTextDatum(name);
			values[1] = TimestampTzGetDatum(r->audit_locked_until); /* DT_NOEND = infinity */
			values[2] = Int32GetDatum(r->failed_count);
			values[3] = BoolGetDatum(!still_locked && !replaced);
			values[4] = Int64GetDatum((int64) r->lost_episodes);
			values[5] = BoolGetDatum(replaced);
			values[6] = BoolGetDatum(dropped);
			values[7] = ObjectIdGetDatum(r->key.roleid);

			/*
			 * lost_episodes: earlier automatic locks of the role whose own
			 * row could not be written before this one overwrote them (worker
			 * late or stopped, standby before promotion; SPEC 6.3).
			 * role_dropped: the role no longer exists (DROP ROLE before
			 * this cycle), role_state was not written.
			 */
			ret = SPI_execute_with_args(
										"SELECT pass_policy.audit('role_locked', $1, "
										"pg_catalog.jsonb_build_object('locked_until', $2, 'failed_count', $3, "
										"'locked_by', 'auto', 'role_oid', $8, "
										"'reason', 'too many failed authentication attempts') "
										"OPERATOR(pg_catalog.||) CASE WHEN $4 THEN "
										"pg_catalog.jsonb_build_object('lifted_before_audit', true) "
										"ELSE '{}'::pg_catalog.jsonb END "
										"OPERATOR(pg_catalog.||) CASE WHEN $6 THEN "
										"pg_catalog.jsonb_build_object('replaced_by_manual', true) "
										"ELSE '{}'::pg_catalog.jsonb END "
										"OPERATOR(pg_catalog.||) CASE WHEN $5 OPERATOR(pg_catalog.>) 0 THEN "
										"pg_catalog.jsonb_build_object('lost_episodes', $5) "
										"ELSE '{}'::pg_catalog.jsonb END "
										"OPERATOR(pg_catalog.||) CASE WHEN $7 THEN "
										"pg_catalog.jsonb_build_object('role_dropped', true) "
										"ELSE '{}'::pg_catalog.jsonb END)",
										8, argtypes, values, NULL, false, 0);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "audit('role_locked') returned SPI code %d", ret);
		}
	}

	/*
	 * The upsert above wrote values copied at the start of this step.  A
	 * lock_role() / unlock_role() committed in between (or whose row lock
	 * the upsert waited for) would be overwritten: role_state would show
	 * the automatic lock again, and the reload of this very cycle would copy
	 * it back to shared memory (its lock_seq is older than the snapshot).
	 * Such a change always bumps the lock_seq of the entry before its row
	 * lock is released (XACT_EVENT_COMMIT callbacks run before the locks are
	 * released), so comparing lock_seq now, before our COMMIT, is enough:
	 * on a change the transaction is rolled back, nothing is acknowledged,
	 * and the next cycle starts again from fresh values.  lock_inflight
	 * covers a lock applied at PRE_COMMIT, not yet committed.
	 */
	{
		const char *changed = NULL;

		LWLockAcquire(ppp_shared->lock, LW_SHARED);
		for (i = 0; i < nrows && changed == NULL; i++)
		{
			if (!rows[i].state_written)
				continue;
			entry = (pppRoleEntry *) hash_search(ppp_role_hash, &rows[i].key,
												 HASH_FIND, NULL);
			if (entry == NULL || entry->lock_seq != rows[i].lock_seq ||
				entry->lock_inflight > 0)
				changed = rows[i].rolename;
		}
		LWLockRelease(ppp_shared->lock);

		if (changed != NULL)
			ereport(ERROR,
					(errmsg(PPP_LOG_PREFIX "lock of role \"%s\" changed while its automatic lock was being written",
							changed),
					 errdetail("The pending audit rows are written again at the next cycle.")));
	}

	if (ghost_names > 0)
	{
		Oid			argtypes[4] = {INT4OID, INT8OID, INT4OID, TIMESTAMPTZOID};
		Datum		values[4];
		char		nulls[4] = {' ', ' ', ' ', ' '};
		int			ret;

		values[0] = Int32GetDatum(ghost_names);
		values[1] = Int64GetDatum(ghost_attempts);
		values[2] = Int32GetDatum(ghost_locks);
		values[3] = TimestampTzGetDatum(ghost_last);
		if (ghost_last == 0)
			nulls[3] = 'n';

		ret = SPI_execute_with_args(
									"SELECT pass_policy.audit('auth_failed', NULL, "
									"pg_catalog.jsonb_build_object('unknown_roles', $1, 'attempts', $2, "
									"'pseudo_locks', $3, 'last_failure_at', $4, 'source', 'auth_hook'))",
									4, argtypes, values, nulls, false, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "audit('auth_failed') of unknown roles returned SPI code %d", ret);
	}

	if (nrows > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "wrote %d pending shared memory entries (%d pseudo-entries, aggregated)",
			 nrows, ghost_names);
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
		pppRoleEntry *entry;

		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &r->key,
											 HASH_FIND, NULL);
		if (entry == NULL)
			continue;

		/*
		 * The entry found under this key may not be the one copied: it may
		 * have been evicted and entered again in between, its episode
		 * numbers starting again from 0.  Such an entry (another
		 * incarnation, told by its generation even when both episode
		 * numbers are 0; or, as a second guard, an episode number behind
		 * the copied one, or the same number for another lock) is left as
		 * it is: what it holds, failures included, was not written, and it
		 * is written at the next cycle.  audit_acked_seq thus never gets
		 * ahead of audit_lock_seq, and lost_episodes stays meaningful.
		 * "Another lock" is told by its end and by when it was set: two
		 * locks until manual unlock (DT_NOEND) have the same end.
		 */
		if (entry->generation != r->generation ||
			(int32) (entry->audit_lock_seq - r->audit_lock_seq) < 0 ||
			(r->lock_pending_audit &&
			 entry->audit_lock_seq == r->audit_lock_seq &&
			 (entry->audit_locked_until != r->audit_locked_until ||
			  entry->audit_lock_set_at != r->audit_lock_set_at)))
			continue;

		entry->pending_failures -= r->pending_failures;
		if (entry->pending_failures < 0)
			entry->pending_failures = 0;

		/*
		 * A lock set again since (later episode) stays pending; the
		 * episodes up to the one written are acknowledged, the pending flag
		 * is only cleared for the very lock written.
		 */
		if (r->lock_pending_audit)
		{
			if (entry->audit_lock_seq == r->audit_lock_seq)
				entry->lock_pending_audit = false;
			if ((int32) (r->audit_lock_seq - entry->audit_acked_seq) > 0)
				entry->audit_acked_seq = r->audit_lock_seq;
		}
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
 * Step 3a: dropped roles, expired locks and inactive entries
 * ------------------------------------------------------------------------
 */
/* lock of a dropped role released by ppp_sync_cleanup(), logged afterwards */
typedef struct pppReleasedRow
{
	Oid			roleid;
	char		rolename[NAMEDATALEN];
} pppReleasedRow;

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
	int			dropped = 0;
	int			removed = 0;
	int			released = 0;
	bool		in_recovery = RecoveryInProgress();
	Oid		   *oids;
	pppReleasedRow *rel;
	int			noids = 0;
	int			ngone = 0;
	int			maxoids;
	int			i;

	/*
	 * Entries of dropped roles.  The OIDs of the real entries that are not
	 * inactive (an inactive entry is purged below anyway) and not already
	 * flagged are copied under a shared lock, looked up outside it (no
	 * catalog access under an LWLock), and those that no longer exist are
	 * handled under the exclusive lock:
	 * - a settled entry (nothing left to audit) is removed: its lock and
	 *	 profile applied to the dropped role only (LOG for a lock);
	 * - otherwise the entry is flagged role_dropped: its lock and profile no
	 *	 longer count (ppp_entry_class), its audit is written by the next
	 *	 pending audit step, after which it is inactive and purged.
	 * No incarnation check is needed: an OID that no longer exists never
	 * comes back (barring wraparound, SPEC 12), and the authentication hook
	 * only creates an entry for an OID its own lookup found, before the
	 * DROP: that entry is indeed the entry of the dropped role.
	 */
	oids = (Oid *) ppp_alloc_hash_copy(CurrentMemoryContext, sizeof(Oid),
									   &maxoids, LW_SHARED);
	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		if (!OidIsValid(entry->key.roleid) || entry->role_dropped ||
			ppp_entry_class(entry, now, in_recovery) == PPP_CLASS_INACTIVE)
			continue;
		if (noids >= maxoids)
		{
			hash_seq_term(&seq);
			break;
		}
		oids[noids++] = entry->key.roleid;
	}
	LWLockRelease(ppp_shared->lock);

	for (i = 0; i < noids; i++)
		if (!SearchSysCacheExists1(AUTHOID, ObjectIdGetDatum(oids[i])))
			oids[ngone++] = oids[i];
	rel = (pppReleasedRow *) palloc(sizeof(pppReleasedRow) * Max(ngone, 1));

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (i = 0; i < ngone; i++)
	{
		pppRoleKey	key;

		ppp_make_key(&key, oids[i], NULL);
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND,
											 NULL);
		if (entry == NULL)
			continue;
		if (ppp_entry_settled(entry))
		{
			if (ppp_is_locked(entry, now))
			{
				rel[released].roleid = oids[i];
				strlcpy(rel[released].rolename, entry->rolename, NAMEDATALEN);
				released++;
			}
			hash_search(ppp_role_hash, &key, HASH_REMOVE, NULL);
			removed++;
		}
		else if (!entry->role_dropped)
		{
			entry->role_dropped = true;
			dropped++;
		}
	}

	hash_seq_init(&seq, ppp_role_hash);
	while ((entry = (pppRoleEntry *) hash_seq_search(&seq)) != NULL)
	{
		pppEntryClass c;

		/*
		 * Expired lock (cleared once its role_locked audit row has been
		 * written).  The authentication hook may already have counted new
		 * failures after the expiry while locked_until was still set: those
		 * belong to a new episode (first_failure_at >= locked_until) and are
		 * kept.
		 */
		(void) ppp_expire_lock(entry, now, true);

		/*
		 * Purge (removing the current element during a hash_seq_search scan
		 * is allowed):
		 * - inactive entries (zero counter or elapsed window, nothing to
		 *	 audit, no lock, no profile; entries of dropped roles once
		 *	 audited);
		 * - live counters without a window (failure_window <= 0) whose last
		 *	 failure is older than PPP_PURGE_AFTER_SECS;
		 * - pseudo-entries once their last failure is older than their
		 *	 failure window (PPP_PURGE_AFTER_SECS if <= 0), unless they still
		 *	 hold an active pseudo-lock.
		 * Entries carrying profile parameters are kept (they are rebuilt on
		 * reload anyway).  An entry with something to audit is never purged
		 * here, even when its class makes it evictable (expired lock whose
		 * audit is stale, PPP_STALE_AUDIT_SECS; pseudo-entry): it is only
		 * given up when the room is needed.
		 */
		if (entry->lock_pending_audit || entry->pending_failures > 0)
			continue;
		if (!OidIsValid(entry->key.roleid))
		{
			int64		window_secs = entry->failure_window_secs > 0 ?
				entry->failure_window_secs : PPP_PURGE_AFTER_SECS;

			if (!ppp_is_locked(entry, now) &&
				entry->last_failure_at <
				TimestampTzPlusMilliseconds(now, -window_secs * 1000))
			{
				hash_search(ppp_role_hash, &entry->key, HASH_REMOVE, NULL);
				purged_missing++;
			}
			continue;
		}
		c = ppp_entry_class(entry, now, in_recovery);
		if (c == PPP_CLASS_INACTIVE ||
			(c == PPP_CLASS_LIVE_COUNTER &&
			 entry->last_failure_at < purge_before))
		{
			hash_search(ppp_role_hash, &entry->key, HASH_REMOVE, NULL);
			purged++;
		}
	}

	/*
	 * Entries purged or removed, or flagged role_dropped (no longer
	 * PPP_CLASS_KEEP): room is free again, a series of fruitless eviction
	 * scans of the authentication hook (ppp_enter_role) is over, and so is
	 * the one-second pause that followed a complete fruitless tour.
	 */
	if (purged > 0 || purged_missing > 0 || dropped > 0 || removed > 0)
	{
		ppp_shared->evict_fruitless_active = false;
		ppp_shared->evict_failed_at = 0;
	}
	LWLockRelease(ppp_shared->lock);

	for (i = 0; i < released; i++)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "lock of dropped role \"%s\" released",
						rel[i].rolename),
				 errdetail("The role of OID %u no longer exists; its lock is audited, and a role created under this name has an entry of its own.",
						   rel[i].roleid)));
	pfree(rel);
	pfree(oids);

	if (dropped > 0 || removed > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "%d shared memory entries of dropped roles removed, %d kept until audited",
			 removed, dropped);
	if (purged > 0 || purged_missing > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "purged %d inactive shared memory entries and %d pseudo-entries",
			 purged, purged_missing);
}

/* ------------------------------------------------------------------------
 * Step 3b: reload profiles and persisted locks
 * ------------------------------------------------------------------------
 */
/* add an eviction made by ppp_enter_role() to the totals of a reload */
static void
ppp_count_eviction(const pppEviction *ev, int *n_evicted, int *lost_failed,
				   int *lost_pending, int *lost_lock_audits)
{
	if (!ev->evicted)
		return;
	(*n_evicted)++;
	*lost_failed += ev->lost_failed_count;
	*lost_pending += ev->lost_pending_failures;
	if (ev->lost_lock_audit)
		(*lost_lock_audits)++;
}

/*
 * Returns false when some persisted locks could not be re-injected (hash full
 * of entries that cannot be evicted): the reload must be retried, and the
 * start-up window of the hook is not closed by it.
 */
static bool
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
	int			locks_not_tracked = 0;
	int			n_evicted = 0;
	int			lost_failed = 0;
	int			lost_pending = 0;
	int			lost_lock_audits = 0;
	int			n_lifted = 0;
	TimestampTz now;
	uint64		seq_snap;
	bool		in_recovery;
	bool		start_window_kept = false;

	/*
	 * Durations (PPP_SQL_WINDOW_SECS, PPP_SQL_LOCK_SECS) are clamped to
	 * INT_MAX seconds (about 68 years) before the int4 cast: a longer
	 * (legal) interval, or 'infinity', would otherwise raise "integer out of
	 * range" at every cycle.  They are also raised to at least one second:
	 * the cast rounds, and a lock_duration under half a second would give
	 * locked_until = now (a lock that never holds), a failure_window under
	 * half a second 0 (no window at all).  The profile CHECK constraints
	 * already refuse such values; this is defence in depth.  NULL
	 * lock_duration (manual unlock only) stays -1, a zero failure_window
	 * (no window) stays 0.
	 */
	/*
	 * Read ppp_shared->lock_seq, then take a fresh snapshot for the queries
	 * below: a lock or unlock stamped with a greater lock_seq (or still in
	 * flight) may have been committed after that snapshot, and must not be
	 * overwritten nor lifted from what we read (ppp_finish_pending_ops in
	 * lockout.c stamps entries once their transaction is visible).
	 * GetLatestSnapshot() also works under REPEATABLE READ or SERIALIZABLE.
	 */
	LWLockAcquire(ppp_shared->lock, LW_SHARED);
	seq_snap = ppp_shared->lock_seq;
	LWLockRelease(ppp_shared->lock);

	PushActiveSnapshot(GetLatestSnapshot());

	/* profile "default" */
	ret = SPI_execute("SELECT p.max_failures, "
					  PPP_SQL_WINDOW_SECS ", "
					  PPP_SQL_LOCK_SECS " "
					  "FROM pass_policy.profile p WHERE p.name = 'default'",
					  true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "reading profile \"default\" returned SPI code %d", ret);
	if (SPI_processed > 0)
	{
		HeapTuple	tup = SPI_tuptable->vals[0];
		TupleDesc	desc = SPI_tuptable->tupdesc;

		have_default = true;
		def_max = ppp_spi_get_int32(tup, desc, 1, 0);
		def_window = ppp_spi_get_int32(tup, desc, 2, 0);
		def_lock = ppp_spi_get_int32(tup, desc, 3, -1);
	}

	/*
	 * Roles with an assigned profile, by OID (current name for messages):
	 * rows of this cluster only (SPEC 6.3, "Rechargement"; a restored row
	 * is inert until run_maintenance() binds it).  A row whose OID no
	 * longer exists (dropped role, purged by run_maintenance()) is left
	 * out: it would otherwise give a from_profile entry (PPP_CLASS_KEEP,
	 * never evicted) to nobody.
	 */
	ret = SPI_execute("SELECT a.oid, a.rolname::text, p.max_failures, "
					  PPP_SQL_WINDOW_SECS ", "
					  PPP_SQL_LOCK_SECS " "
					  "FROM pass_policy.role_profile rp "
					  "JOIN pass_policy.profile p USING (profile_id) "
					  "JOIN pg_catalog.pg_authid a ON a.oid = rp.role_oid "
					  "WHERE rp.cluster_id = pass_policy._system_identifier()",
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
			char	   *name = SPI_getvalue(tup, desc, 2);
			bool		isnull;

			profiles[i].roleid = DatumGetObjectId(SPI_getbinval(tup, desc, 1, &isnull));
			if (isnull)
				profiles[i].roleid = InvalidOid;
			memset(profiles[i].rolename, 0, NAMEDATALEN);
			if (name)
				strlcpy(profiles[i].rolename, name, NAMEDATALEN);
			profiles[i].max_failures = ppp_spi_get_int32(tup, desc, 3, 0);
			profiles[i].failure_window_secs = ppp_spi_get_int32(tup, desc, 4, 0);
			profiles[i].lock_duration_secs = ppp_spi_get_int32(tup, desc, 5, -1);
		}
	}

	/*
	 * Persisted active locks ('infinity' comes back as DT_NOEND), by OID,
	 * rows of this cluster only, as the profiles above: a row whose OID no
	 * longer exists (dropped role, purged by run_maintenance()) is ignored,
	 * whoever bears its name now.
	 */
	ret = SPI_execute("SELECT a.oid, a.rolname::text, s.locked_until "
					  "FROM pass_policy.role_state s "
					  "JOIN pg_catalog.pg_authid a ON a.oid = s.role_oid "
					  "WHERE s.cluster_id = pass_policy._system_identifier() "
					  "AND s.locked_until IS NOT NULL AND s.locked_until > now()",
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
			char	   *name = SPI_getvalue(tup, desc, 2);
			bool		isnull;
			Datum		d;

			locks[i].roleid = DatumGetObjectId(SPI_getbinval(tup, desc, 1, &isnull));
			if (isnull)
				locks[i].roleid = InvalidOid;
			memset(locks[i].rolename, 0, NAMEDATALEN);
			if (name)
				strlcpy(locks[i].rolename, name, NAMEDATALEN);
			d = SPI_getbinval(tup, desc, 3, &isnull);
			locks[i].locked_until = isnull ? 0 : DatumGetTimestampTz(d);
		}
	}

	/*
	 * Restored rows not bound yet: they apply nothing until run_maintenance()
	 * or rebind_restored_roles() binds them (SPEC §12); told once an hour.
	 */
	ret = SPI_execute("SELECT pass_policy._unbound_count()", true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed != 1)
		elog(ERROR, "_unbound_count() returned SPI code %d", ret);
	{
		bool		isnull;
		int64		unbound = DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0],
														  SPI_tuptable->tupdesc, 1,
														  &isnull));

		if (isnull || unbound == 0)
			ppp_unbound_logged_at = 0;	/* a new restore is told at once */
		else if (ppp_log_due(&ppp_unbound_logged_at, GetCurrentTimestamp(),
							 PPP_UNBOUND_LOG_SECS * 1000))
			ereport(WARNING,
					(errmsg_plural(PPP_LOG_PREFIX "%lld row restored from another cluster is not bound: run pass_policy.run_maintenance() or rebind_restored_roles()",
								   PPP_LOG_PREFIX "%lld rows restored from another cluster are not bound: run pass_policy.run_maintenance() or rebind_restored_roles()",
								   (unsigned long) unbound, (long long) unbound),
					 errdetail("Rows of role_state and role_profile restored from another cluster apply no lock and no profile until they are bound to their role (at most one message per hour).")));
	}

	PopActiveSnapshot();


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
		pppRoleKey	key;

		if (!OidIsValid(locks[i].roleid) || locks[i].locked_until == 0)
			continue;

		ppp_make_key(&key, locks[i].roleid, NULL);
		entry = ppp_enter_role(&key, locks[i].rolename, PPP_ENTER_PRIORITY,
							   now, in_recovery, &ev);
		ppp_count_eviction(&ev, &n_evicted, &lost_failed, &lost_pending,
						   &lost_lock_audits);
		if (entry == NULL)
		{
			not_tracked++;
			locks_not_tracked++;
			continue;
		}
		entry->reload_lock_seen = true;
		strlcpy(entry->rolename, locks[i].rolename, NAMEDATALEN);

		/* changed by shmem_lock_role() / shmem_unlock_role() since our snapshot */
		if (entry->lock_inflight > 0 || entry->lock_seq > seq_snap)
			continue;

		/*
		 * lock_pending_audit is left alone: an automatic lock not yet
		 * audited is written from audit_locked_until, and only copied to
		 * role_state while locked_until still equals it.
		 */
		if (entry->locked_until != locks[i].locked_until)
			entry->lock_set_at = now;
		entry->locked_until = locks[i].locked_until;
		entry->lock_from_state = true;
	}

	/* roles with an assigned profile */
	for (i = 0; i < nprofiles; i++)
	{
		pppEviction ev;
		pppRoleKey	key;

		if (!OidIsValid(profiles[i].roleid))
			continue;

		ppp_make_key(&key, profiles[i].roleid, NULL);
		entry = ppp_enter_role(&key, profiles[i].rolename, PPP_ENTER_PRIORITY,
							   now, in_recovery, &ev);
		ppp_count_eviction(&ev, &n_evicted, &lost_failed, &lost_pending,
						   &lost_lock_audits);
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
		strlcpy(entry->rolename, profiles[i].rolename, NAMEDATALEN);
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
		 * A lock mirrored in role_state (re-injected from it, or set by
		 * shmem_lock_role() on a primary) that is no longer there has been
		 * lifted (unlock_role(), expiry, on the primary for a standby), or
		 * its transaction failed after PRE_COMMIT: lift it.  Only when it
		 * has not changed since our snapshot (lock_inflight, lock_seq), so
		 * that a lock_role() committed after the snapshot is never lifted.
		 * Automatic locks of the authentication hook (lock_from_state
		 * false) are left alone: the pending audit step copies them to
		 * role_state, on a standby they expire or are lifted with
		 * shmem_unlock_role().
		 */
		if (entry->lock_from_state && !entry->reload_lock_seen &&
			entry->lock_inflight == 0 && entry->lock_seq <= seq_snap)
		{
			entry->locked_until = 0;
			entry->lock_from_state = false;
			n_lifted++;
		}
	}

	ppp_shared->worker_last_reload = GetCurrentTimestamp();

	/*
	 * Closes the fail-closed start-up window of the hook, unless a persisted
	 * lock could not be loaded: the hook would let that role in.  A profile
	 * that could not be loaded does not keep the window closed (the role is
	 * counted with the default parameters, as before the window).
	 */
	if (locks_not_tracked == 0)
		ppp_shared->locks_loaded = true;
	else
		start_window_kept = !ppp_shared->locks_loaded;

	LWLockRelease(ppp_shared->lock);

	if (start_window_kept &&
		ppp_log_due(&ppp_window_kept_logged_at, GetCurrentTimestamp(),
					PPP_WINDOW_KEPT_LOG_SECS * 1000))
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "%d persisted locks could not be loaded in shared memory: connections stay refused",
						locks_not_tracked),
				 errdetail("Until every lock of role_state is loaded, roles authenticating with a password or a secret are refused (57P03), superusers included, except pg_pass_policy.exempt_roles and the superusers of pg_pass_policy.rescue_roles through peer; the reload is retried every few seconds (at most one message per minute)."),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));

	if (not_tracked > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "%d roles could not be loaded in shared memory: too many tracked roles",
						not_tracked),
				 errdetail("Every entry holds a lock or profile parameters."),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));
	if (lost_failed > 0 || lost_pending > 0 || lost_lock_audits > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "shared memory full: %d entries evicted to load locks and profiles (%d counted failures, %d failures not yet audited, %d expired locks not yet audited lost)",
						n_evicted, lost_failed, lost_pending, lost_lock_audits),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));
	else if (n_evicted > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "shared memory full: %d inactive entries evicted to load locks and profiles",
			 n_evicted);
	if (n_lifted > 0)
		elog(DEBUG1, PPP_LOG_PREFIX "%d locks no longer in role_state removed from shared memory",
			 n_lifted);

	elog(DEBUG1, PPP_LOG_PREFIX "reloaded lockout parameters: " UINT64_FORMAT " role profiles, " UINT64_FORMAT " locks",
		 nprofiles, nlocks);

	return locks_not_tracked == 0;
}

static void
ppp_step_sync(void)
{
	ppp_flush_rescue_log();
	ppp_sync_cleanup();
	/* kept pending when some persisted locks could not be loaded */
	if (ppp_reload_pending && ppp_sync_reload())
		ppp_reload_pending = false;
	/* again: a start-up window closed by this reload is flushed at once */
	ppp_flush_rescue_log();
}

/*
 * One cycle.  run_full = false: shared memory synchronisation only
 * (worker_interval = 0).  retry_only: woken up by the PPP_RETRY_SECS retry
 * of a failed first synchronisation (start-up window held open), not by the
 * regular timer nor a request: if that synchronisation fails again, the rest
 * of the cycle (maintenance, pending audit, second synchronisation) is
 * skipped; it runs at the regular pace only.
 */
static void
ppp_worker_cycle(bool run_full, bool retry_only)
{
	pgstat_report_activity(STATE_RUNNING, "pg_pass_policy maintenance");

	/*
	 * First cycle, after promotion or after enabled is turned on again:
	 * re-inject the persisted locks before anything else (see
	 * ppp_sync_first).  The request is consumed here: run_maintenance()
	 * makes a new one, served by the synchronisation step at the end of this
	 * cycle.  On failure (error, persisted locks that do not all fit in
	 * shared memory), ppp_reload_pending stays set and the next cycle starts
	 * over.  An extension that is not installed leaves nothing to reload
	 * (see ppp_run_in_xact).
	 */
	if (ppp_sync_first)
	{
		(void) pg_atomic_exchange_u32(&ppp_shared->reload_requested, 0);
		ppp_reload_pending = true;
		(void) ppp_run_in_xact("shared memory synchronisation", ppp_step_sync);
		if (!ppp_reload_pending)
			ppp_sync_first = false;
		else if (retry_only)
		{
			pgstat_report_activity(STATE_IDLE, NULL);
			return;
		}

		CHECK_FOR_INTERRUPTS();
	}

	if (run_full)
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
	ppp_full_cycle_at = GetCurrentTimestamp();

	pgstat_report_activity(STATE_IDLE, NULL);
}

/*
 * Read-only cycle of a hot standby.
 *
 * run_maintenance() and the pending audit step write and cannot run.  The
 * failures and locks counted here by the authentication hook stay pending
 * (pending_failures, lock_pending_audit): the entries of existing roles
 * cannot be evicted by the hook meanwhile, and the first cycle after
 * promotion writes their audit rows and copies the locks to role_state.
 * The shared memory hash must still be filled from the replicated role_state
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

	(void) ppp_run_in_xact("standby synchronisation", ppp_step_sync);

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	ppp_shared->worker_last_run = GetCurrentTimestamp();
	LWLockRelease(ppp_shared->lock);

	pgstat_report_activity(STATE_IDLE, NULL);
}

/*
 * pg_pass_policy.enabled = off: the worker modifies nothing (the GUC
 * description promises it), neither the tables (run_maintenance(), pending
 * audit rows, role_state) nor the shared memory (clean-up, reload).  A
 * reload request is turned into ppp_reload_pending so that it is not lost;
 * the first cycle once enabled again forces a reload anyway, since profiles
 * or role_state may have changed meanwhile (restore).  worker_last_run is
 * not updated: worker_status() shows when the worker last did its job.
 * Logs the transitions once.
 */
static bool
ppp_worker_suspended(void)
{
	static bool suspended = false;

	if (!ppp_enabled)
	{
		if (pg_atomic_exchange_u32(&ppp_shared->reload_requested, 0) != 0)
			ppp_reload_pending = true;
		if (!suspended)
			ereport(LOG,
					(errmsg(PPP_LOG_PREFIX "worker suspended: pg_pass_policy.enabled is off"),
					 errdetail("Pending audit rows and locks stay in shared memory until it is turned on again.")));
		suspended = true;
		return true;
	}
	if (suspended)
	{
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "worker resumed: pg_pass_policy.enabled is on")));
		suspended = false;
		ppp_reload_pending = true;
		ppp_sync_first = true;
	}
	return false;
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

	pg_atomic_write_u32(&ppp_shared->worker_pid, (uint32) MyProcPid);
	on_shmem_exit(ppp_worker_on_exit, (Datum) 0);

	ereport(LOG,
			(errmsg(PPP_LOG_PREFIX "worker started on database \"%s\"",
					ppp_database)));

	for (;;)
	{
		long		timeout;
		int			events;
		int			rc;
		bool		retry;
		bool		requested = false;
		bool		retry_only;

		CHECK_FOR_INTERRUPTS();

		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
			run_now = true;
			requested = true;
		}

		if (pg_atomic_read_u32(&ppp_shared->reload_requested) != 0)
		{
			run_now = true;
			requested = true;
		}

		if (run_now && !ppp_worker_suspended())
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
					ppp_sync_first = true;
					was_in_recovery = false;
				}

				/*
				 * While the first synchronisation keeps failing (start-up
				 * window held open), the PPP_RETRY_SECS wake-ups only retry
				 * it; the whole cycle still runs at the regular pace
				 * (worker_interval), on a request, and the first time.
				 */
				retry_only = ppp_sync_first && !requested &&
					ppp_full_cycle_at != 0 &&
					(ppp_worker_interval <= 0 ||
					 !TimestampDifferenceExceeds(ppp_full_cycle_at,
												 GetCurrentTimestamp(),
												 ppp_worker_interval * 1000));
				ppp_worker_cycle(ppp_worker_interval > 0, retry_only);
			}
			MemoryContextSwitchTo(oldcxt);
			MemoryContextReset(ppp_worker_cxt);
		}
		run_now = false;

		/*
		 * interval = 0: sleep until signalled.  On a standby nothing signals
		 * the changes replicated from the primary: always poll, every
		 * worker_interval (60 s when it is 0), which also detects promotion.
		 *
		 * While the start-up window is open (!locks_loaded), retry at most
		 * PPP_RETRY_SECS later whatever worker_interval, on a standby too:
		 * every role authenticating with a password is refused meanwhile.
		 * With worker_interval = 0, a pending reload (failed, nothing would
		 * wake the worker up again) is retried that way too.  Suspended
		 * (enabled = off): the hook does nothing, no need to retry.
		 */
		events = WL_LATCH_SET | WL_EXIT_ON_PM_DEATH;
		retry = ppp_enabled &&
			(!ppp_shared->locks_loaded ||
			 (ppp_reload_pending && ppp_worker_interval == 0));
		if (retry)
			timeout = (ppp_worker_interval > 0 ?
					   Min(ppp_worker_interval, PPP_RETRY_SECS) :
					   PPP_RETRY_SECS) * 1000L;
		else if (RecoveryInProgress())
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
