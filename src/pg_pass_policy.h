/*
 * pg_pass_policy.h — contrat C partagé entre pg_pass_policy.c, policy.c,
 * lockout.c et worker.c. Voir docs/SPEC.md §6.
 */
#ifndef PG_PASS_POLICY_H
#define PG_PASS_POLICY_H

#include "postgres.h"
#include "datatype/timestamp.h"
#include "port/atomics.h"
#include "storage/lwlock.h"
#include "utils/hsearch.h"

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

	/* maintained by the worker */
	bool		lock_from_state;		/* locked_until re-injected from role_state */
	bool		role_missing;			/* not in pg_authid at the last cleanup */
	bool		reload_profile_seen;	/* scratch marks of ppp_sync_reload() */
	bool		reload_lock_seen;
} pppRoleEntry;

/*
 * Entry creation when the hash is full (SPEC 6.3):
 * - PPP_ENTER_COUNT: plain failure counting (authentication hook), limited
 *   to ppp_count_entry_limit() entries; only evicts worthless entries
 *   (zero counter, elapsed window or non-existent role);
 * - PPP_ENTER_PRIORITY: lock, re-injection from role_state or profile; may
 *   use the reserve and evict any entry without lock nor profile.
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
	char		rolename[NAMEDATALEN];
	int32		lost_failed_count;		/* counter still inside its window */
	int32		lost_pending_failures;	/* failures lost before being audited */
} pppEviction;

typedef struct pppSharedState
{
	LWLock	   *lock;

	/* valeurs du profil "default", appliquées aux rôles absents du hash */
	int32		default_max_failures;
	int32		default_failure_window_secs;
	int32		default_lock_duration_secs;

	pg_atomic_uint32 reload_requested;	/* posé par shmem_reload(), lu par le worker */
	pid_t		worker_pid;
	TimestampTz worker_last_run;
	TimestampTz worker_last_reload;
} pppSharedState;

extern pppSharedState *ppp_shared;
extern HTAB *ppp_role_hash;

/* ---- pg_pass_policy.c -------------------------------------------------- */
extern Size ppp_shmem_size(void);
extern bool ppp_role_is_exempt(const char *rolename);
/*
 * True only if the pg_pass_policy extension is installed in the current
 * database, its objects live in schema PPP_SCHEMA and that schema is owned by
 * a superuser.  Any SPI call executed with elevated privileges must be gated
 * by this check: a look-alike schema created by an unprivileged user must
 * never be trusted.  Requires a transaction and catalog access.
 */
extern bool ppp_extension_installed(void);
/* efface une zone mémoire contenant un secret avant de la libérer */
extern void ppp_secure_zero(void *p, size_t len);

/* ---- policy.c ---------------------------------------------------------- */
extern void ppp_policy_init(void);		/* installe check_password_hook */

/* ---- lockout.c --------------------------------------------------------- */
extern void ppp_lockout_init(void);		/* installe ClientAuthentication_hook */
extern void ppp_lockout_shmem_init(void); /* appelé depuis shmem_startup_hook */
/* caller holds ppp_shared->lock exclusively; NULL when no room is left */
extern pppRoleEntry *ppp_enter_role(const char *rolename, pppEnterMode mode,
									TimestampTz now, pppEviction *ev);
extern void ppp_log_eviction(const pppEviction *ev);
extern int	ppp_count_entry_limit(void);

/* ---- worker.c ---------------------------------------------------------- */
extern void ppp_worker_register(void);	/* appelé depuis _PG_init */
extern PGDLLEXPORT void ppp_worker_main(Datum main_arg);

#endif							/* PG_PASS_POLICY_H */
