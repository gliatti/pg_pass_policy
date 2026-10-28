/*-------------------------------------------------------------------------
 *
 * pg_pass_policy.c
 *		Module entry point: _PG_init, GUC definitions, shared memory
 *		request/startup, exemption list and small shared helpers.
 *
 * See docs/SPEC.md sections 5 and 6.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <string.h>

#include "access/htup_details.h"
#include "catalog/namespace.h"
#include "catalog/pg_namespace.h"
#include "commands/extension.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "utils/syscache.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"
#include "utils/varlena.h"

#include "pg_pass_policy.h"
#include "compat.h"

PPP_MODULE_MAGIC;

/* ---- GUC variables ----------------------------------------------------- */
bool		ppp_enabled = true;
char	   *ppp_database = NULL;
int			ppp_worker_interval = 60;
int			ppp_max_tracked_roles = 1024;
bool		ppp_manage_valid_until = true;
bool		ppp_log_events = true;
char	   *ppp_notify_channel = NULL;
char	   *ppp_exempt_roles = NULL;
char	   *ppp_rescue_roles = NULL;
bool		ppp_superuser_bypass = false;
bool		ppp_require_scram = true;
bool		ppp_enforce_database = true;

/* ---- shared state ------------------------------------------------------ */
pppSharedState *ppp_shared = NULL;
HTAB	   *ppp_role_hash = NULL;

#ifdef PPP_HAVE_SHMEM_REQUEST_HOOK
static shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

void		_PG_init(void);

PG_FUNCTION_INFO_V1(ppp_worker_status);
PG_FUNCTION_INFO_V1(ppp_worker_pid);
PG_FUNCTION_INFO_V1(ppp_is_exempt);


/*
 * Size of the shared memory segment we need: the fixed state plus the hash
 * table of tracked roles (created by ppp_lockout_shmem_init()).
 */
Size
ppp_shmem_size(void)
{
	Size		size;

	size = MAXALIGN(sizeof(pppSharedState));
	size = add_size(size, hash_estimate_size(ppp_max_tracked_roles,
											 sizeof(pppRoleEntry)));
	return size;
}

static void
ppp_request_shmem(void)
{
	RequestAddinShmemSpace(ppp_shmem_size());
	RequestNamedLWLockTranche(PPP_LWLOCK_TRANCHE, 1);
}

#ifdef PPP_HAVE_SHMEM_REQUEST_HOOK
static void
ppp_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();
	ppp_request_shmem();
}
#endif

static void
ppp_shmem_startup(void)
{
	bool		found;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* reset in case this is a restart within the postmaster */
	ppp_shared = NULL;
	ppp_role_hash = NULL;

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	ppp_shared = ShmemInitStruct("pg_pass_policy shared state",
								 sizeof(pppSharedState), &found);
	/*
	 * Only the first process to get here initialises the state: without
	 * EXEC_BACKEND that is the postmaster, with EXEC_BACKEND every child
	 * runs this hook again and finds the structure.  This is the single
	 * initialisation site of the shared state (the hash table is created by
	 * ppp_lockout_shmem_init(), below).
	 */
	if (!found)
	{
		memset(ppp_shared, 0, sizeof(pppSharedState));
		ppp_shared->lock = &(GetNamedLWLockTranche(PPP_LWLOCK_TRANCHE))->lock;
		/* safe defaults until the worker has read the "default" profile */
		ppp_shared->default_max_failures = PPP_DEFAULT_MAX_FAILURES;
		ppp_shared->default_failure_window_secs = PPP_DEFAULT_FAILURE_WINDOW_SECS;
		ppp_shared->default_lock_duration_secs = PPP_DEFAULT_LOCK_DURATION_SECS;
		/* force a first load of profiles and persisted locks */
		pg_atomic_init_u32(&ppp_shared->reload_requested, 1);
		pg_atomic_init_u32(&ppp_shared->worker_pid, 0);
		ppp_shared->worker_last_run = 0;
		ppp_shared->worker_last_reload = 0;
		/* fail-closed until the worker has re-injected the persisted locks */
		ppp_shared->locks_loaded = false;
		ppp_shared->not_loaded_logged_at = 0;
		ppp_shared->shmem_init_at = GetCurrentTimestamp();
		ppp_shared->worker_missing_logged_at = 0;
		ppp_shared->rescue_logged_at = 0;
	}

	/* the role hash table belongs to lockout.c */
	ppp_lockout_shmem_init();

	LWLockRelease(AddinShmemInitLock);
}

/*
 * pg_pass_policy.exempt_roles, parsed once per assignment.
 *
 * The check hook does all the work that may fail: it splits the value
 * (SplitIdentifierString(), which pallocs and may raise an ERROR on out of
 * memory, as check hooks are allowed to) and builds the result in one
 * GUC "extra" block (PPP_GUC_MALLOC, see compat.h): a pppExemptList
 * followed by the names it points to.  guc.c keeps that block with the
 * value and frees it when the value is discarded.  The assign hook,
 * which must never fail, only copies the pointer, so that
 * ppp_role_is_exempt() (called by both hooks at every password change and
 * every authentication) only compares strings.
 */
typedef struct pppExemptList
{
	int			count;
	char	   *names[FLEXIBLE_ARRAY_MEMBER];	/* point into the same block */
} pppExemptList;

static const pppExemptList *ppp_exempt_list = NULL;

/* pg_pass_policy.rescue_roles, parsed the same way (same check hook) */
static const pppExemptList *ppp_rescue_list = NULL;

/*
 * GUC check hook for pg_pass_policy.exempt_roles and
 * pg_pass_policy.rescue_roles: the value must be a valid comma-separated
 * list of identifiers; the split list is returned in *extra.
 */
static bool
ppp_check_exempt_roles(char **newval, void **extra, GucSource source)
{
	char	   *rawstring;
	List	   *elemlist;
	ListCell   *lc;
	Size		size;
	pppExemptList *list;
	char	   *p;
	int			n = 0;

	rawstring = pstrdup(*newval ? *newval : "");
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		GUC_check_errdetail("List syntax is invalid.");
		list_free(elemlist);
		pfree(rawstring);
		return false;
	}

	size = offsetof(pppExemptList, names) +
		sizeof(char *) * list_length(elemlist);
	foreach(lc, elemlist)
		size += strlen((const char *) lfirst(lc)) + 1;

	list = (pppExemptList *) PPP_GUC_MALLOC(size);
	if (list == NULL)
	{
		GUC_check_errcode(ERRCODE_OUT_OF_MEMORY);
		GUC_check_errdetail("Out of memory.");
		list_free(elemlist);
		pfree(rawstring);
		return false;
	}

	p = (char *) list + offsetof(pppExemptList, names) +
		sizeof(char *) * list_length(elemlist);
	foreach(lc, elemlist)
	{
		const char *name = (const char *) lfirst(lc);
		size_t		len = strlen(name) + 1;

		memcpy(p, name, len);
		list->names[n++] = p;
		p += len;
	}
	list->count = n;

	list_free(elemlist);
	pfree(rawstring);
	*extra = list;
	return true;
}

/*
 * GUC assign hook for pg_pass_policy.exempt_roles: never fails, the list
 * was built by the check hook.
 */
static void
ppp_assign_exempt_roles(const char *newval, void *extra)
{
	ppp_exempt_list = (const pppExemptList *) extra;
}

/* GUC assign hook for pg_pass_policy.rescue_roles (same as above) */
static void
ppp_assign_rescue_roles(const char *newval, void *extra)
{
	ppp_rescue_list = (const pppExemptList *) extra;
}

/*
 * Is rolename in the list parsed from the GUC value raw?  An empty value
 * matches nothing.  The check hook builds the list (extra) for every
 * accepted non-empty value, the boot value included, so it cannot be
 * missing here; should it ever be, nothing matches (fail closed).
 */
static bool
ppp_list_contains(const char *raw, const pppExemptList *list,
				  const char *rolename)
{
	int			i;

	if (rolename == NULL || raw == NULL || raw[0] == '\0')
		return false;

	Assert(list != NULL);
	if (list == NULL)
		return false;

	for (i = 0; i < list->count; i++)
		if (strcmp(list->names[i], rolename) == 0)
			return true;
	return false;
}

/*
 * Is the role exempted from the policy and from the lockout?
 *
 * The list follows the SQL identifier rules of SplitIdentifierString():
 * unquoted names are down-cased, double-quoted names keep their case.  The
 * comparison with the role name is then exact.  pass_policy._is_exempt()
 * is a SQL wrapper of this very function (ppp_is_exempt()).
 *
 * Safe to call from the ClientAuthentication hook (no catalog access).
 */
bool
ppp_role_is_exempt(const char *rolename)
{
	return ppp_list_contains(ppp_exempt_roles, ppp_exempt_list, rolename);
}

/*
 * Is the role listed in pg_pass_policy.rescue_roles, the superusers allowed
 * in by peer authentication during the start-up window (SPEC 6.3,
 * "Démarrage")?  Same parsing rules as exempt_roles; empty (default) = no
 * rescue access.  Safe to call from the ClientAuthentication hook.
 */
bool
ppp_role_is_rescue(const char *rolename)
{
	return ppp_list_contains(ppp_rescue_roles, ppp_rescue_list, rolename);
}

/*
 * pass_policy._is_exempt(role text) RETURNS bool (STRICT, STABLE)
 *
 * SQL access to ppp_role_is_exempt(), used by run_maintenance(),
 * rotate_password() and switch_rotation_pair(): SQL and C hooks share one
 * implementation of the parsing of pg_pass_policy.exempt_roles.
 */
Datum
ppp_is_exempt(PG_FUNCTION_ARGS)
{
	char	   *rolename = text_to_cstring(PG_GETARG_TEXT_PP(0));
	bool		result = ppp_role_is_exempt(rolename);

	pfree(rolename);
	PG_RETURN_BOOL(result);
}

/*
 * ppp_extension_state
 *
 * The password hook runs in every database of the cluster and executes SPI
 * queries as the bootstrap superuser against schema-qualified objects.  Merely
 * finding a schema named PPP_SCHEMA is not enough: a user with CREATE on a
 * database could create a look-alike schema whose effective_profile() would
 * then run with superuser rights.  Trusted = the real extension, bound to
 * that very schema, and a superuser owner of the schema.
 *
 * PPP_EXT_ABSENT: no pg_pass_policy extension in this database (a schema of
 * that name may exist, it is ignored).  PPP_EXT_UNTRUSTED: the extension is
 * installed but one of the other conditions fails (schema re-owned by a
 * non-superuser, owner demoted, schema renamed): the caller must refuse
 * rather than apply no policy.  *nspowner (optional) receives the owner of
 * schema PPP_SCHEMA, InvalidOid if it does not exist.
 */
pppExtensionState
ppp_extension_state(Oid *nspowner)
{
	Oid			extoid;
	Oid			nspoid;
	HeapTuple	tup;
	Oid			owner;

	if (nspowner)
		*nspowner = InvalidOid;

	extoid = get_extension_oid(PPP_LIBRARY_NAME, true);
	if (!OidIsValid(extoid))
		return PPP_EXT_ABSENT;

	nspoid = get_namespace_oid(PPP_SCHEMA, true);
	if (!OidIsValid(nspoid))
		return PPP_EXT_UNTRUSTED;

	tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(nspoid));
	if (!HeapTupleIsValid(tup))
		return PPP_EXT_UNTRUSTED;
	owner = ((Form_pg_namespace) GETSTRUCT(tup))->nspowner;
	ReleaseSysCache(tup);
	if (nspowner)
		*nspowner = owner;

	if (ppp_get_extension_schema(extoid) != nspoid)
		return PPP_EXT_UNTRUSTED;

	return superuser_arg(owner) ? PPP_EXT_TRUSTED : PPP_EXT_UNTRUSTED;
}

/*
 * ppp_untrusted_detail
 *
 * Detail of an untrusted extension (PPP_EXT_UNTRUSTED), shared by the PPP-004
 * error of policy.c and the message of the worker: names the owner of schema
 * PPP_SCHEMA when it is not a superuser.
 */
char *
ppp_untrusted_detail(Oid nspowner)
{
	if (!OidIsValid(nspowner))
		return pstrdup("Schema \"" PPP_SCHEMA "\" does not exist or does not hold the objects of extension pg_pass_policy.");
	if (!superuser_arg(nspowner))
	{
		const char *owner = GetUserNameFromId(nspowner, true);

		return psprintf("Schema \"" PPP_SCHEMA "\" is owned by role \"%s\", which is not a superuser.",
						owner ? owner : "?");
	}
	return pstrdup("The objects of extension pg_pass_policy are not in schema \"" PPP_SCHEMA "\".");
}

/*
 * Wipe memory that held a secret.  explicit_bzero() cannot be optimized away;
 * the volatile loop is the portable fallback.
 */
void
ppp_secure_zero(void *p, size_t len)
{
	if (p == NULL || len == 0)
		return;
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(p, len);
#else
	{
		volatile unsigned char *vp = (volatile unsigned char *) p;

		while (len--)
			*vp++ = 0;
	}
#endif
}

/*
 * int4 column "col" (1-based) of an SPI result row, dflt when NULL.  Shared
 * by policy.c (profile) and worker.c (lockout parameters).
 */
int32
ppp_spi_get_int32(HeapTuple tup, TupleDesc desc, int col, int32 dflt)
{
	bool		isnull;
	Datum		d = SPI_getbinval(tup, desc, col, &isnull);

	return isnull ? dflt : DatumGetInt32(d);
}

/*
 * See pg_pass_policy.h.  The checks are those of InitMaterializedSRF() (PG
 * 15+), which does not exist in PG 14.
 */
void
ppp_begin_materialize(FunctionCallInfo fcinfo, TupleDesc *tupdesc,
					  Tuplestorestate **tupstore, int expected_natts)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	MemoryContext oldcontext;
	TupleDesc	desc;

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not allowed in this context")));
	if (get_call_result_type(fcinfo, NULL, &desc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");
	if (expected_natts > 0 && desc->natts != expected_natts)
		elog(ERROR, "function must be declared with %d output columns",
			 expected_natts);

	oldcontext = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);
	desc = CreateTupleDescCopy(desc);
	*tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = *tupstore;
	rsinfo->setDesc = desc;
	MemoryContextSwitchTo(oldcontext);

	*tupdesc = desc;
}

/*
 * pass_policy.worker_status()
 *		RETURNS TABLE(pid int, last_run timestamptz, last_reload timestamptz,
 *					  tracked_roles int, locks_loaded bool)
 *
 * locks_loaded: the fail-closed start-up window is closed (SPEC 6.3,
 * "Démarrage"); false while roles authenticating with a secret are refused
 * with 57P03.
 */
Datum
ppp_worker_status(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	Datum		values[5];
	bool		nulls[5];
	pid_t		pid;
	TimestampTz last_run;
	TimestampTz last_reload;
	int32		tracked = 0;
	bool		locks_loaded;

	if (ppp_shared == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_pass_policy must be loaded via shared_preload_libraries")));

	ppp_begin_materialize(fcinfo, &tupdesc, &tupstore, 5);

	LWLockAcquire(ppp_shared->lock, LW_SHARED);
	pid = ppp_get_worker_pid();
	last_run = ppp_shared->worker_last_run;
	last_reload = ppp_shared->worker_last_reload;
	locks_loaded = ppp_shared->locks_loaded;
	if (ppp_role_hash != NULL)
		tracked = (int32) hash_get_num_entries(ppp_role_hash);
	LWLockRelease(ppp_shared->lock);

	memset(nulls, 0, sizeof(nulls));
	values[0] = Int32GetDatum((int32) pid);
	nulls[0] = (pid == 0);
	values[1] = TimestampTzGetDatum(last_run);
	nulls[1] = (last_run == 0);
	values[2] = TimestampTzGetDatum(last_reload);
	nulls[2] = (last_reload == 0);
	values[3] = Int32GetDatum(tracked);
	values[4] = BoolGetDatum(locks_loaded);

	tuplestore_putvalues(tupstore, tupdesc, values, nulls);

	return (Datum) 0;
}

/*
 * pass_policy._worker_pid() RETURNS int
 *
 * PID of the background worker, NULL when it is not running (or when the
 * shared memory is not initialised).  Called by _audit() for every audit
 * row: a single atomic read, no lock, no tuplestore.
 */
Datum
ppp_worker_pid(PG_FUNCTION_ARGS)
{
	pid_t		pid;

	if (ppp_shared == NULL)
		PG_RETURN_NULL();

	pid = ppp_get_worker_pid();
	if (pid == 0)
		PG_RETURN_NULL();
	PG_RETURN_INT32((int32) pid);
}

void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_pass_policy must be loaded via shared_preload_libraries"),
				 errhint("Add pg_pass_policy to shared_preload_libraries in postgresql.conf and restart the server.")));

	DefineCustomBoolVariable("pg_pass_policy.enabled",
							 "Enables the password policy and the lockout.",
							 "When off, the hooks do nothing and the background worker does not modify anything.",
							 &ppp_enabled,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("pg_pass_policy.database",
							   "Database where the pg_pass_policy extension is installed.",
							   "The background worker connects to this database.",
							   &ppp_database,
							   "postgres",
							   PGC_POSTMASTER,
							   0,
							   NULL, NULL, NULL);

	DefineCustomIntVariable("pg_pass_policy.worker_interval",
							"Interval between two maintenance runs of the background worker.",
							"0 disables the periodic run (run_maintenance() must then be called manually).",
							&ppp_worker_interval,
							60,
							0,
							INT_MAX / 1000,
							PGC_SIGHUP,
							GUC_UNIT_S,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_pass_policy.max_tracked_roles",
							"Maximum number of roles tracked in shared memory by the lockout.",
							NULL,
							&ppp_max_tracked_roles,
							1024,
							16,
							1048576,
							PGC_POSTMASTER,
							0,
							NULL, NULL, NULL);

	DefineCustomBoolVariable("pg_pass_policy.manage_valid_until",
							 "Lets the background worker write pg_authid.rolvaliduntil.",
							 NULL,
							 &ppp_manage_valid_until,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("pg_pass_policy.log_events",
							 "Logs every pg_pass_policy event in the server log.",
							 NULL,
							 &ppp_log_events,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("pg_pass_policy.notify_channel",
							   "NOTIFY channel used for pg_pass_policy events.",
							   NULL,
							   &ppp_notify_channel,
							   "pg_pass_policy",
							   PGC_SIGHUP,
							   0,
							   NULL, NULL, NULL);

	DefineCustomStringVariable("pg_pass_policy.exempt_roles",
							   "Comma-separated list of roles exempted from the policy and the lockout.",
							   "Unquoted names are down-cased like SQL identifiers.",
							   &ppp_exempt_roles,
							   "",
							   PGC_SIGHUP,
							   GUC_LIST_INPUT,
							   ppp_check_exempt_roles, ppp_assign_exempt_roles, NULL);

	DefineCustomStringVariable("pg_pass_policy.rescue_roles",
							   "Comma-separated list of superusers admitted by peer authentication before the lock state is loaded.",
							   "Unquoted names are down-cased like SQL identifiers. Empty: no such rescue access.",
							   &ppp_rescue_roles,
							   "",
							   PGC_SIGHUP,
							   GUC_LIST_INPUT,
							   ppp_check_exempt_roles, ppp_assign_rescue_roles, NULL);

	DefineCustomBoolVariable("pg_pass_policy.superuser_bypass",
							 "Superusers setting a password are not subject to the complexity rules.",
							 NULL,
							 &ppp_superuser_bypass,
							 false,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("pg_pass_policy.require_scram",
							 "Rejects MD5 passwords.",
							 NULL,
							 &ppp_require_scram,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("pg_pass_policy.enforce_database",
							 "Rejects password changes made outside pg_pass_policy.database.",
							 "When off, such changes are only accepted with a WARNING.",
							 &ppp_enforce_database,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	PPP_RESERVE_GUC_PREFIX("pg_pass_policy");

	/* shared memory */
#ifdef PPP_HAVE_SHMEM_REQUEST_HOOK
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = ppp_shmem_request;
#else
	ppp_request_shmem();
#endif
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = ppp_shmem_startup;

	/* hooks and background worker */
	ppp_policy_init();
	ppp_lockout_init();
	ppp_worker_register();
}
