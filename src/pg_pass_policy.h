/*
 * pg_pass_policy.h — contrat C partagé entre pg_pass_policy.c, policy.c,
 * lockout.c et worker.c. Voir docs/SPEC.md §6.
 */
#ifndef PG_PASS_POLICY_H
#define PG_PASS_POLICY_H

#include "postgres.h"
#include "access/htup.h"
#include "access/tupdesc.h"
#include "datatype/timestamp.h"
#include "fmgr.h"
#include "port/atomics.h"
#include "storage/lwlock.h"
#include "utils/hsearch.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"

#define PPP_SCHEMA        "pass_policy"
#define PPP_LIBRARY_NAME  "pg_pass_policy"
#define PPP_LWLOCK_TRANCHE "pg_pass_policy"
#define PPP_LOG_PREFIX    "pg_pass_policy: "

/* ---- GUC (définis dans pg_pass_policy.c) ---------------------------------- */
extern bool  ppp_enabled;
extern char *ppp_database;
extern int   ppp_worker_interval;      /* secondes, 0 = worker en sommeil */
extern int   ppp_max_tracked_roles;    /* taille du hash shmem (postmaster) */
extern bool  ppp_manage_valid_until;
extern bool  ppp_log_events;
extern char *ppp_notify_channel;
extern char *ppp_exempt_roles;         /* liste séparée par des virgules */
extern bool  ppp_superuser_bypass;
extern bool  ppp_require_scram;
extern bool  ppp_enforce_database;

/*
 * Lockout parameters used until the worker has read the "default" profile
 * (same values as the defaults of SPEC 3.1).  Single definition, applied by
 * ppp_shmem_startup() (pg_pass_policy.c).
 */
#define PPP_DEFAULT_MAX_FAILURES		5
#define PPP_DEFAULT_FAILURE_WINDOW_SECS	(15 * 60)
#define PPP_DEFAULT_LOCK_DURATION_SECS	(30 * 60)

/*
 * Fail-closed start-up window (SPEC 6.3, "Démarrage"): once the shared
 * memory has been initialised for that long without any worker having
 * published its PID, the worker is considered missing: the authentication
 * hook logs it (at most once per PPP_WORKER_MISSING_LOG_SECS) and lets the
 * superusers through (the other non-exempt roles stay refused).
 */
#define PPP_WORKER_MISSING_GRACE_SECS	10
#define PPP_WORKER_MISSING_LOG_SECS		60

/* ---- Mémoire partagée (remplie par le worker, lue par le hook auth) ------- */
typedef struct pppRoleKey
{
	char		rolename[NAMEDATALEN];
} pppRoleKey;

typedef struct pppRoleEntry
{
	pppRoleKey	key;

	/* paramètres copiés depuis le profil effectif par le worker */
	int32		max_failures;			/* 0 = verrouillage désactivé */
	int32		failure_window_secs;
	int32		lock_duration_secs;		/* -1 = déverrouillage manuel */
	bool		from_profile;			/* false = valeurs par défaut */

	/* compteurs maintenus par le hook d'authentification */
	int32		failed_count;
	TimestampTz first_failure_at;
	TimestampTz last_failure_at;
	TimestampTz locked_until;			/* 0 = non verrouillé, DT_NOEND = manuel */
	bool		lock_pending_audit;		/* posé par le hook, effacé par le worker */
	int32		pending_failures;		/* échecs non encore journalisés */

	/*
	 * locked_until of the automatic lock whose role_locked audit row is
	 * pending (lock_pending_audit).  Kept apart from locked_until so that
	 * an unlock, or a manual lock, applied before the worker has written
	 * the row does not lose it: the worker audits this value, and copies it
	 * to role_state only while locked_until still equals it.
	 */
	TimestampTz audit_locked_until;

	/*
	 * Automatic lock episodes.  audit_lock_seq is incremented by the
	 * authentication hook at every automatic lock; audit_acked_seq is the
	 * episode whose role_locked row was last written (acknowledged by the
	 * worker), or the last episode when none is pending.  When a new lock
	 * overwrites audit_locked_until before the worker has written the
	 * previous one, audit_lock_seq - audit_acked_seq - 1 episodes have lost
	 * their own row: the worker reports that count in the details of the row
	 * it writes (lost_episodes) instead.
	 */
	uint32		audit_lock_seq;
	uint32		audit_acked_seq;

	/*
	 * When locked_until was last set to a new lock (authentication hook,
	 * PRE_COMMIT of shmem_lock_role(), re-injection by the worker).  An
	 * unlock committed afterwards only lifts a lock set before it was
	 * requested (pppPendingOp.queued_at in lockout.c), so that a newer
	 * automatic lock survives an unlock decided on older data.
	 */
	TimestampTz lock_set_at;

	/*
	 * Lock state.  lock_from_state: the lock is expected to be mirrored in
	 * role_state (re-injected by the worker, or set by shmem_lock_role() on
	 * a primary): a reload lifts it when role_state no longer holds it.
	 * lock_inflight / lock_seq: see ppp_shared->lock_seq.
	 */
	bool		lock_from_state;
	uint32		lock_inflight;			/* PPP_OP_LOCK applied, not yet committed */
	uint64		lock_seq;				/* ppp_shared->lock_seq of the last change */

	/* set by the authentication hook: user name not found in pg_authid */
	bool		role_missing;

	/* scratch marks of ppp_sync_reload() */
	bool		reload_profile_seen;
	bool		reload_lock_seen;
} pppRoleEntry;

/*
 * Classes of entries, from the cheapest to lose to the most expensive one
 * (SPEC 6.3).  Single definition used by the authentication hook, the
 * eviction (ppp_enter_role) and the worker purge (ppp_sync_cleanup).
 */
typedef enum pppEntryClass
{
	PPP_CLASS_GHOST = 0,		/* role_missing: always evictable */
	PPP_CLASS_INACTIVE,			/* zero counter or elapsed window, nothing
								 * pending, no lock, no profile; also an
								 * expired lock whose audit is stale (see
								 * PPP_STALE_AUDIT_SECS) */
	PPP_CLASS_LIVE_COUNTER,		/* failure counter still inside its window */
	PPP_CLASS_PENDING_AUDIT,	/* failures not yet written to audit_log */
	PPP_CLASS_KEEP				/* active lock, lock not yet audited, or
								 * profile parameters: never evicted */
} pppEntryClass;

/*
 * An expired lock whose role_locked audit row is still pending
 * (lock_pending_audit) stops being PPP_CLASS_KEEP once it ended more than
 * this long ago, or at once on a hot standby (the row cannot be written
 * before a promotion): otherwise a worker that cannot write (standby,
 * pg_pass_policy.database misconfigured) would let such entries fill the
 * hash for good.  The entry is then classified on its counter only, and
 * the loss of its pending audit is logged if it is evicted.
 */
#define PPP_STALE_AUDIT_SECS	(24 * 60 * 60)

/*
 * Maximum number of entries examined by one eviction scan in PPP_ENTER_COUNT
 * mode (authentication hook), under the exclusive lock.  PPP_ENTER_PRIORITY
 * (locks, re-injection, profiles: rare, made by administrators or the
 * worker) still scans the whole hash.
 */
#define PPP_EVICT_SCAN_LIMIT	256

/*
 * Entry creation when the hash is full (SPEC 6.3):
 * - PPP_ENTER_COUNT: plain failure counting (authentication hook); evicts
 *   PPP_CLASS_GHOST then PPP_CLASS_INACTIVE entries only;
 * - PPP_ENTER_PRIORITY: lock, re-injection from role_state or profile; may
 *   also evict PPP_CLASS_LIVE_COUNTER then PPP_CLASS_PENDING_AUDIT entries.
 */
typedef enum pppEnterMode
{
	PPP_ENTER_COUNT,
	PPP_ENTER_PRIORITY
} pppEnterMode;

/* entry evicted by ppp_enter_role(), to be logged once the lock is released */
typedef struct pppEviction
{
	bool		evicted;
	bool		ghost;					/* evicted entry was a non-existent role */
	bool		scan_skipped;			/* COUNT mode: no room, but no conclusive
										 * scan (skipped after a recent fruitless
										 * one, or fruitless window of a cycle
										 * not finished yet): not logged */
	char		rolename[NAMEDATALEN];
	int32		lost_failed_count;		/* counter still inside its window */
	int32		lost_pending_failures;	/* failures lost before being audited */
	bool		lost_lock_audit;		/* role_locked row lost (stale, see
										 * PPP_STALE_AUDIT_SECS) */
	pppRoleEntry victim;				/* content of the evicted entry, so that
										 * an aborted lock can put it back */
} pppEviction;

typedef struct pppSharedState
{
	LWLock	   *lock;

	/* valeurs du profil "default", appliquées aux rôles absents du hash */
	int32		default_max_failures;
	int32		default_failure_window_secs;
	int32		default_lock_duration_secs;

	pg_atomic_uint32 reload_requested;	/* posé par shmem_reload(), lu par le worker */
	/*
	 * PID of the running worker, 0 if none.  Atomic rather than under
	 * "lock": the worker clears it from its on_shmem_exit callback, which
	 * may run while it still holds the LWLock (FATAL), and LWLockAcquire()
	 * would then wait for itself.  Read with ppp_get_worker_pid().
	 */
	pg_atomic_uint32 worker_pid;
	TimestampTz worker_last_run;
	TimestampTz worker_last_reload;

	/*
	 * Fail-closed start-up window (SPEC 6.3, "Démarrage"): false from
	 * shared memory initialisation until the worker has re-injected the
	 * persisted locks (ppp_sync_reload), or found that the extension is not
	 * installed in pg_pass_policy.database (nothing to re-inject).  Until
	 * then the authentication hook refuses the non-exempt roles that
	 * authenticate with a secret (57P03), and does not count their
	 * failures; superusers are let through only while the worker is
	 * demonstrably missing (worker_pid = 0 PPP_WORKER_MISSING_GRACE_SECS
	 * after shmem_init_at).  not_loaded_logged_at limits its LOG to one per second
	 * across all backends.  shmem_init_at is the time of the shared memory
	 * initialisation; worker_missing_logged_at limits to one per minute the
	 * LOG of the hook when no worker has published its PID
	 * (worker_pid = 0) PPP_WORKER_MISSING_GRACE_SECS after it: the worker
	 * was never started (max_worker_processes exhausted) or cannot connect
	 * (pg_pass_policy.database does not exist).
	 */
	bool		locks_loaded;
	TimestampTz not_loaded_logged_at;
	TimestampTz shmem_init_at;
	TimestampTz worker_missing_logged_at;

	/*
	 * Last time an eviction scan in PPP_ENTER_COUNT mode found nothing to
	 * evict: the authentication hook skips the scan for one second after
	 * that, so that a flood of failed connections against a hash full of
	 * locks and profiles does not scan it under the exclusive lock at every
	 * attempt.
	 */
	TimestampTz evict_failed_at;

	/*
	 * Bounded eviction scan of PPP_ENTER_COUNT mode (ppp_enter_role): the
	 * hook examines at most PPP_EVICT_SCAN_LIMIT entries per attempt,
	 * starting from the bucket where the previous scan stopped
	 * (evict_scan_bucket).  evict_scan_fruitless counts the entries examined
	 * since an evictable one was last found; once it reaches the number of
	 * entries, the whole hash has been examined in vain and evict_failed_at
	 * is set.
	 */
	uint32		evict_scan_bucket;
	int64		evict_scan_fruitless;

	/*
	 * Incremented (under the lock) each time a lock or unlock requested
	 * through shmem_lock_role() / shmem_unlock_role() is committed or
	 * aborted; the entry keeps the value in lock_seq.  The worker reads it
	 * before taking the snapshot used to reload role_state: an entry whose
	 * lock_seq is greater, or whose lock_inflight is not zero, has changed
	 * after that snapshot and is left alone by the reload.
	 */
	uint64		lock_seq;
} pppSharedState;

extern pppSharedState *ppp_shared;
extern HTAB *ppp_role_hash;

/* ---- pg_pass_policy.c -------------------------------------------------- */
extern Size ppp_shmem_size(void);
extern bool ppp_role_is_exempt(const char *rolename);
/*
 * State of the pg_pass_policy extension in the current database.  Trusted
 * only if it is installed, its objects live in schema PPP_SCHEMA and that
 * schema is owned by a superuser: any SPI call executed with elevated
 * privileges must be gated by this check, a look-alike schema created by an
 * unprivileged user must never be trusted.  The password hook and the SQL
 * functions of policy.c go through ppp_require_extension() (policy.c), which
 * raises PPP-004 for an installed but untrusted extension instead of
 * silently applying no policy; the background worker calls
 * ppp_extension_state() itself (an absent extension closes the start-up
 * window, an untrusted one does not).  *nspowner (optional) receives the
 * owner of schema PPP_SCHEMA, InvalidOid if none.  Requires a transaction
 * and catalog access.
 */
typedef enum pppExtensionState
{
	PPP_EXT_ABSENT,				/* extension not installed in this database */
	PPP_EXT_TRUSTED,			/* installed in PPP_SCHEMA, superuser owner */
	PPP_EXT_UNTRUSTED			/* installed, but schema missing, elsewhere or
								 * not owned by a superuser */
} pppExtensionState;

extern pppExtensionState ppp_extension_state(Oid *nspowner);
/*
 * Why an installed extension is not trusted, for an errdetail (palloc'd):
 * nspowner as returned by ppp_extension_state().  Requires a transaction.
 */
extern char *ppp_untrusted_detail(Oid nspowner);

/*
 * Common start of a materialize-mode set-returning function: checks the
 * call context, builds the result descriptor (expected_natts output
 * columns, checked when > 0) and an empty tuplestore in the per-query
 * context, and registers both in fcinfo->resultinfo.  Written by hand
 * (rather than with InitMaterializedSRF) so that it works on PG 14 to 18.
 */
extern void ppp_begin_materialize(FunctionCallInfo fcinfo, TupleDesc *tupdesc,
								  Tuplestorestate **tupstore,
								  int expected_natts);
/* colonne int4 (numéro 1-based) d'une ligne SPI, dflt si NULL */
extern int32 ppp_spi_get_int32(HeapTuple tup, TupleDesc desc, int col,
							   int32 dflt);
/* efface une zone mémoire contenant un secret avant de la libérer */
extern void ppp_secure_zero(void *p, size_t len);

/* ---- policy.c ---------------------------------------------------------- */
extern void ppp_policy_init(void);		/* installe check_password_hook */

/* ---- lockout.c --------------------------------------------------------- */
/*
 * Hash key of a role name, truncated like the server does for
 * port->user_name (plain byte truncation to NAMEDATALEN - 1), zero-padded.
 */
extern void ppp_make_key(pppRoleKey *key, const char *rolename);
extern void ppp_lockout_init(void);		/* installe ClientAuthentication_hook */
extern void ppp_lockout_shmem_init(void); /* appelé depuis shmem_startup_hook */
/*
 * Changement de mot de passe enregistré par le hook dans la transaction
 * courante (pass_policy._record_done()) : drapeau local au backend, remis
 * à zéro au COMMIT / ABORT et à l'annulation de sa sous-transaction.
 */
extern void ppp_note_password_recorded(const char *rolename);
extern bool ppp_password_recorded(const char *rolename);
/*
 * Caller holds ppp_shared->lock exclusively; NULL when no room is left.
 * in_recovery: RecoveryInProgress(), read before taking the lock (see
 * PPP_STALE_AUDIT_SECS).
 */
extern pppRoleEntry *ppp_enter_role(const char *rolename, pppEnterMode mode,
									TimestampTz now, bool in_recovery,
									pppEviction *ev);
extern void ppp_log_eviction(const pppEviction *ev);
/*
 * Allocate in cxt one row of rowsize bytes per hash entry (plus
 * PPP_HASH_COPY_MARGIN), then return with ppp_shared->lock held in mode;
 * *maxrows bounds the copy made under the lock.
 */
#define PPP_HASH_COPY_MARGIN	16
extern void *ppp_alloc_hash_copy(MemoryContext cxt, Size rowsize,
								 int *maxrows, LWLockMode mode);
/* failure_window_secs > 0 and elapsed since first_failure_at */
extern bool ppp_window_elapsed(const pppRoleEntry *entry, TimestampTz now);
/* class of an entry; ppp_entry_real_class() ignores role_missing */
extern pppEntryClass ppp_entry_class(const pppRoleEntry *entry, TimestampTz now,
									 bool in_recovery);
extern pppEntryClass ppp_entry_real_class(const pppRoleEntry *entry,
										  TimestampTz now, bool in_recovery);

/*
 * Forget an expired lock (caller holds ppp_shared->lock exclusively); see
 * lockout.c.  Returns true when locked_until was cleared.
 */
extern bool ppp_expire_lock(pppRoleEntry *entry, TimestampTz now,
							bool check_inflight);

/* PID of the background worker, 0 when it is not running */
static inline pid_t
ppp_get_worker_pid(void)
{
	return (pid_t) pg_atomic_read_u32(&ppp_shared->worker_pid);
}

/* Is the lock of an entry active at time "now"? */
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
 * Rate limiter of a message: true (and *last set to now) when no message was
 * emitted yet (*last = 0) or the last one is at least msec old.  The caller
 * serialises the access to *last (ppp_shared->lock for the shared ones).
 */
static inline bool
ppp_log_due(TimestampTz *last, TimestampTz now, int msec)
{
	if (*last != 0 && !TimestampDifferenceExceeds(*last, now, msec))
		return false;
	*last = now;
	return true;
}

/* ---- worker.c ---------------------------------------------------------- */
extern void ppp_worker_register(void);	/* appelé depuis _PG_init */
extern PGDLLEXPORT void ppp_worker_main(Datum main_arg);

#endif							/* PG_PASS_POLICY_H */
