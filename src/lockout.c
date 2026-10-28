/*-------------------------------------------------------------------------
 *
 * lockout.c
 *		Account lockout after repeated authentication failures.
 *
 * The ClientAuthentication_hook runs during InitPostgres(), after the
 * catalog caches have been initialised and a transaction has been started
 * (PerformAuthentication() is called once StartTransactionCommand() and
 * GetTransactionSnapshot() have run: checked in the sources of 13.2, 16.4
 * and 17beta1): syscache lookups work there, as get_role_password() itself
 * does SearchSysCache1(AUTHNAME).  The hook makes one lookup (AUTHNAME) at
 * every connection it handles, before taking any LWLock: the OID of the
 * role is the key of its entry (pppRoleKey), and the lookup also tells
 * whether its rolvaliduntil has passed and whether it is a superuser; no
 * SPI.  Should the hook ever run outside a transaction, it refuses the
 * connection (57P03, fail-closed).  Everything else lives in shared memory
 * (ppp_role_hash), which is filled by the background worker (profile
 * parameters, persisted locks) and read back by the worker to write audit
 * rows and role_state (worker.c).
 *
 * This file also provides the C functions exposed in SQL:
 *	 failed_attempts(), shmem_reload(), shmem_lock_role(),
 *	 shmem_unlock_role(), shmem_reset_failures().
 *
 * Shared memory is not transactional while the SQL functions that call the
 * shmem_* functions are (lock_role() updates role_state, then the shared
 * memory, in one transaction).  The writes requested by shmem_lock_role(),
 * shmem_unlock_role() and shmem_reset_failures(), and the signal sent by
 * shmem_reload(), are therefore deferred to the end of the calling
 * transaction through a transaction callback (ppp_xact_callback), with
 * sub-transaction support: a ROLLBACK (TO SAVEPOINT) discards them.  Locks
 * are applied at PRE_COMMIT (where an ERROR still aborts the transaction),
 * unlocks and counter resets at COMMIT (once the transaction is durable).
 *
 * See docs/SPEC.md, sections 4 and 6.3.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <signal.h>

#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/pg_authid.h"
#include "common/hashfn.h"
#include "fmgr.h"
#include "funcapi.h"
#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"

#include "pg_pass_policy.h"
#include "compat.h"

PG_FUNCTION_INFO_V1(ppp_failed_attempts);
PG_FUNCTION_INFO_V1(ppp_shmem_reload);
PG_FUNCTION_INFO_V1(ppp_shmem_lock_role);
PG_FUNCTION_INFO_V1(ppp_shmem_unlock_role);
PG_FUNCTION_INFO_V1(ppp_shmem_reset_failures);
PG_FUNCTION_INFO_V1(ppp_shmem_is_locked);
PG_FUNCTION_INFO_V1(ppp_shmem_lock_oid);
PG_FUNCTION_INFO_V1(ppp_shmem_unlock_oid);
PG_FUNCTION_INFO_V1(ppp_shmem_reset_oid);
PG_FUNCTION_INFO_V1(ppp_system_identifier);

static ClientAuthentication_hook_type prev_client_auth_hook = NULL;

static void ppp_client_auth_hook(Port *port, int status);
static void ppp_signal_worker_reload(void);


/* the key is hashed and compared as a whole: no padding byte */
StaticAssertDecl(sizeof(pppRoleKey) == sizeof(Oid) + NAMEDATALEN,
				 "pppRoleKey must not contain padding");

/*
 * Build a hash key (see pppRoleKey): the OID of an existing role, or, when
 * roleid is InvalidOid, the name, truncated like the server does for
 * port->user_name (plain byte truncation to NAMEDATALEN - 1).  The key is
 * zeroed first: dynahash compares it with memcmp().
 */
void
ppp_make_key(pppRoleKey *key, Oid roleid, const char *name)
{
	memset(key, 0, sizeof(pppRoleKey));
	if (OidIsValid(roleid))
		key->roleid = roleid;
	else
		strlcpy(key->name, name, NAMEDATALEN);
}

/*
 * Hash function of ppp_role_hash (HASH_FUNCTION).  A real key hashes its
 * OID (hash_bytes_uint32, as uint32_hash does); a pseudo-key hashes its
 * name as string_hash would (hash_bytes over strlen bytes), that is the
 * value of hashtext(name COLLATE "C"), which test/shell/hashfull.sh uses to
 * place a name in a chosen bucket.
 */
static uint32
ppp_key_hash(const void *key, Size keysize)
{
	const pppRoleKey *k = (const pppRoleKey *) key;

	if (OidIsValid(k->roleid))
		return hash_bytes_uint32((uint32) k->roleid);
	return hash_bytes((const unsigned char *) k->name,
					  (int) strnlen(k->name, NAMEDATALEN - 1));
}

/*
 * Initialise a freshly entered hash entry with the default parameters.
 * Caller must hold ppp_shared->lock exclusively.
 */
static void
ppp_init_entry(pppRoleEntry *entry, const char *rolename)
{
	strlcpy(entry->rolename, rolename, NAMEDATALEN);
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
	entry->audit_locked_until = 0;
	entry->audit_lock_seq = 0;
	entry->audit_acked_seq = 0;
	entry->audit_lock_set_at = 0;
	entry->lock_set_at = 0;
	entry->lock_from_state = false;
	entry->lock_inflight = 0;
	entry->lock_seq = 0;
	entry->generation = ++ppp_shared->entry_generation;
	entry->role_dropped = false;
	entry->reload_profile_seen = false;
	entry->reload_lock_seen = false;
}

/*
 * Has the failure window of an entry elapsed?  A window <= 0 means "no
 * window": failures add up until a success, the window never elapses.
 */
bool
ppp_window_elapsed(const pppRoleEntry *entry, TimestampTz now)
{
	return entry->failure_window_secs > 0 &&
		now - entry->first_failure_at >
		(int64) entry->failure_window_secs * USECS_PER_SEC;
}

/*
 * Is the pending role_locked audit of an entry whose lock is no longer
 * active stale (see PPP_STALE_AUDIT_SECS)?  On a hot standby it is at once:
 * the row cannot be written before a promotion.  Otherwise the reference is
 * the end of the audited lock; for a lock until manual unlock (DT_NOEND),
 * lifted since, only the time it was set is known.
 */
static bool
ppp_lock_audit_stale(const pppRoleEntry *entry, TimestampTz now,
					 bool in_recovery)
{
	TimestampTz ended = entry->audit_locked_until;

	if (in_recovery)
		return true;
	if (ended == 0 || ended == DT_NOEND)
		ended = entry->lock_set_at;
	return now - ended > (int64) PPP_STALE_AUDIT_SECS * USECS_PER_SEC;
}

/*
 * Class of an entry (see pppEntryClass).  Caller holds ppp_shared->lock.
 * in_recovery: RecoveryInProgress(), read by the caller before taking the
 * lock.
 *
 * A pseudo-entry (key without OID: a user name that matched no role) is
 * always PPP_CLASS_GHOST, even when it holds a pseudo-lock or failures not
 * yet audited: losing them is harmless (the name cannot log in anyway, and
 * a role created later under that name has its own entry, keyed by its
 * OID), whereas keeping them would let a client that tries many
 * non-existent names fill the hash and prevent the failures of real roles
 * from being counted.
 *
 * The entry of a dropped role (role_dropped) keeps only its pending audit:
 * PPP_CLASS_PENDING_AUDIT while it has one, PPP_CLASS_INACTIVE otherwise;
 * its lock and profile apply to nobody any more.
 *
 * An expired lock whose audit is stale is classified on its counter only:
 * the failures and the lock it has not audited yet are given up (and
 * logged, ppp_log_eviction) if the entry is evicted.  The worker never
 * purges such an entry by itself (ppp_sync_cleanup): it only becomes
 * evictable when the room is needed.
 *
 * The failures that led to an expired lock are forgotten (ppp_expire_lock),
 * but only once the hook meets that role again or the worker runs its next
 * cycle: until then failed_count still holds them.  They are not a live
 * counter, so the class must not depend on whether that reset has happened.
 */
pppEntryClass
ppp_entry_class(const pppRoleEntry *entry, TimestampTz now, bool in_recovery)
{
	if (!OidIsValid(entry->key.roleid))
		return PPP_CLASS_GHOST;
	if (entry->role_dropped)
		return (entry->lock_pending_audit || entry->pending_failures > 0) ?
			PPP_CLASS_PENDING_AUDIT : PPP_CLASS_INACTIVE;
	if (entry->from_profile || ppp_is_locked(entry, now))
		return PPP_CLASS_KEEP;
	if (entry->lock_pending_audit)
	{
		if (!ppp_lock_audit_stale(entry, now, in_recovery))
			return PPP_CLASS_KEEP;
	}
	else if (entry->pending_failures > 0)
		return PPP_CLASS_PENDING_AUDIT;
	if (entry->failed_count <= 0 || ppp_window_elapsed(entry, now))
		return PPP_CLASS_INACTIVE;
	/* expired lock, counters of its episode not reset yet (see above) */
	if (entry->locked_until != 0 && entry->lock_inflight == 0 &&
		entry->first_failure_at < entry->locked_until)
		return PPP_CLASS_INACTIVE;
	return PPP_CLASS_LIVE_COUNTER;
}

/*
 * Forget an expired lock.  The failures that led to it (first_failure_at
 * predates the end of the lock) are forgotten, once: later attempts are
 * counted afresh while locked_until stays set.  locked_until itself is kept
 * while the worker has not written the role_locked audit row yet
 * (lock_pending_audit; a later call clears it once the row is written).
 * check_inflight: leave alone an entry whose lock, applied at PRE_COMMIT,
 * is not committed yet (the worker; the authentication hook only cares
 * whether the lock is active).  Caller holds ppp_shared->lock exclusively.
 * Returns true when locked_until was cleared.
 */
bool
ppp_expire_lock(pppRoleEntry *entry, TimestampTz now, bool check_inflight)
{
	if (entry->locked_until == 0 || ppp_is_locked(entry, now))
		return false;
	if (check_inflight && entry->lock_inflight > 0)
		return false;

	if (entry->first_failure_at < entry->locked_until)
	{
		entry->failed_count = 0;
		entry->first_failure_at = 0;
	}
	if (entry->lock_pending_audit)
		return false;

	entry->locked_until = 0;
	entry->lock_from_state = false;
	return true;
}

/*
 * Find or create the entry of a role.  Caller must hold ppp_shared->lock
 * exclusively.  Returns NULL when there is no room left.
 *
 * When the hash is full (max_tracked_roles entries), the least recently
 * failed entry of the cheapest class allowed for the mode is removed to
 * make room:
 *	 - PPP_ENTER_COUNT evicts PPP_CLASS_GHOST, then PPP_CLASS_INACTIVE
 *	   entries: evicting a live counter would let an attacker reset the
 *	   counter of the role he is brute-forcing by trying many other existing
 *	   user names;
 *	 - PPP_ENTER_PRIORITY also evicts PPP_CLASS_LIVE_COUNTER, then
 *	   PPP_CLASS_PENDING_AUDIT entries: a lock or profile is worth more than
 *	   a failure counter or a few audit rows.
 * PPP_CLASS_KEEP entries are never evicted.  The evicted entry is described
 * in *ev (which may be NULL) so that the caller can log it once the lock is
 * released (ppp_log_eviction); ev->victim keeps its whole content, so that
 * a caller that gives the room back (ppp_apply_lock_ops on error) can put
 * the entry back.
 *
 * The scan only happens once the hash is full.  In PPP_ENTER_PRIORITY mode
 * (rare: locks, re-injection, profiles) it examines the whole hash.  In
 * PPP_ENTER_COUNT mode (every failed connection) it is bounded: at most
 * PPP_EVICT_SCAN_LIMIT entries are examined, from the bucket where the
 * previous scan stopped (ppp_shared->evict_scan_bucket), and the victim is
 * the best one of that window.  A fruitless window is treated as "no room"
 * for this attempt (ev->scan_skipped, not logged); once fruitless windows
 * have covered every bucket (ppp_shared->evict_fruitless_*: one real tour of
 * the buckets, whatever the number of entries examined twice when a scan
 * resumes in the middle of a chain), the scan is
 * not repeated for one second (ppp_shared->evict_failed_at): the hash is
 * then full of entries the hook may not evict, and a flood of failed
 * connections would otherwise keep scanning it under the exclusive lock.
 *
 * Resuming a scan sets HASH_SEQ_STATUS.curBucket after hash_seq_init(),
 * whose only other effect is to register the scan: the structure is
 * documented as opaque, but its fields and the way hash_seq_search() reads
 * curBucket are unchanged in PG 13 to 18 (PG 18 adds hasHashvalue, which
 * hash_seq_init() sets to false).  A curBucket beyond max_bucket simply
 * ends the scan, which then restarts from bucket 0.
 *
 * The explicit size check is needed: a shared hash can grow beyond its
 * max_size as long as the shared memory segment has free space left.
 */
pppRoleEntry *
ppp_enter_role(const pppRoleKey *key, const char *rolename, pppEnterMode mode,
			   TimestampTz now, bool in_recovery, pppEviction *ev)
{
	pppRoleEntry *entry;
	bool		found;

	if (ev)
		memset(ev, 0, sizeof(pppEviction));

	entry = (pppRoleEntry *) hash_search(ppp_role_hash, key, HASH_FIND, NULL);
	if (entry)
		return entry;

	if (hash_get_num_entries(ppp_role_hash) >= ppp_max_tracked_roles)
	{
		pppEntryClass max_class = (mode == PPP_ENTER_PRIORITY) ?
			PPP_CLASS_PENDING_AUDIT : PPP_CLASS_INACTIVE;
		pppEntryClass best_class = PPP_CLASS_KEEP;
		pppRoleEntry *victim = NULL;
		HASH_SEQ_STATUS seq;
		pppRoleEntry *e;
		long		nentries = hash_get_num_entries(ppp_role_hash);
		long		limit = nentries;
		long		examined = 0;
		long		examined_at_end = -1;	/* examined when the end was first
											 * reached, -1 = not reached */
		uint32		start_bucket = 0;
		uint32		next_bucket = 0;
		bool		wrapped;
		bool		scanning;

		if (mode == PPP_ENTER_COUNT && ppp_shared->evict_failed_at != 0 &&
			now >= ppp_shared->evict_failed_at &&
			now - ppp_shared->evict_failed_at < USECS_PER_SEC)
		{
			if (ev)
				ev->scan_skipped = true;
			return NULL;
		}

		hash_seq_init(&seq, ppp_role_hash);
		if (mode == PPP_ENTER_COUNT)
		{
			limit = Min(nentries, PPP_EVICT_SCAN_LIMIT);
			start_bucket = ppp_shared->evict_scan_bucket;
			seq.curBucket = start_bucket;
		}
		/* a scan started at bucket 0 has nothing to wrap around to */
		wrapped = (start_bucket == 0);
		scanning = true;

		while (examined < limit)
		{
			pppEntryClass c;

			e = (pppRoleEntry *) hash_seq_search(&seq);
			if (e == NULL)
			{
				/* hash_seq_search() has terminated the scan */
				if (examined_at_end < 0)
					examined_at_end = examined;
				if (wrapped)
				{
					scanning = false;
					break;
				}
				wrapped = true;
				hash_seq_init(&seq, ppp_role_hash);
				continue;
			}

			examined++;
			c = ppp_entry_class(e, now, in_recovery);
			if (c > max_class)
				continue;
			if (victim == NULL || c < best_class ||
				(c == best_class && e->last_failure_at < victim->last_failure_at))
			{
				victim = e;
				best_class = c;
			}
		}

		if (mode == PPP_ENTER_COUNT)
		{
			if (scanning)
			{
				/*
				 * Stopped by the limit.  In the middle of a chain, the next
				 * scan restarts at the beginning of that bucket (a few
				 * entries examined twice), unless no progress would be
				 * made.
				 */
				next_bucket = seq.curBucket;
				if (seq.curEntry != NULL && next_bucket == start_bucket)
					next_bucket++;
			}
			ppp_shared->evict_scan_bucket = next_bucket;
		}
		if (scanning)
			hash_seq_term(&seq);

		if (victim == NULL)
		{
			if (mode == PPP_ENTER_COUNT)
			{
				bool		toured;

				/*
				 * Follow the series of fruitless scans by bucket positions:
				 * the buckets examined so far are those from
				 * evict_fruitless_from to next_bucket, past the last bucket
				 * once evict_fruitless_wrapped is set.  A scan that reached
				 * the end before examining any entry (resumed beyond the
				 * last non-empty bucket) starts its series at bucket 0.
				 */
				if (!ppp_shared->evict_fruitless_active)
				{
					ppp_shared->evict_fruitless_active = true;
					if (examined_at_end == 0)
					{
						ppp_shared->evict_fruitless_from = 0;
						ppp_shared->evict_fruitless_wrapped = false;
					}
					else
					{
						ppp_shared->evict_fruitless_from = start_bucket;
						ppp_shared->evict_fruitless_wrapped = (examined_at_end > 0);
					}
				}
				else if (examined_at_end >= 0)
					ppp_shared->evict_fruitless_wrapped = true;

				/*
				 * !scanning, or every entry examined (limit = nentries,
				 * stopped by the limit just before its start bucket): this
				 * scan alone went round the whole hash.  Without the second
				 * test, a scan whose start bucket follows empty buckets
				 * stops after the last entry before them (next_bucket <
				 * evict_fruitless_from), the next one starts there and stops
				 * at the same place: the series never completed, the LOG
				 * and the one-second pause never came.
				 */
				toured = !scanning || examined >= nentries ||
					(ppp_shared->evict_fruitless_wrapped &&
					 next_bucket >= ppp_shared->evict_fruitless_from);
				if (toured)
				{
					/* every bucket examined in vain: give up for a second */
					ppp_shared->evict_failed_at = now;
					ppp_shared->evict_fruitless_active = false;
				}
				else if (ev)
					ev->scan_skipped = true;
			}
			return NULL;
		}

		/*
		 * A victim found, by either mode: the hash has changed, the series
		 * of fruitless scans (if any) no longer describes it, nor does the
		 * pause that followed a complete fruitless tour.
		 */
		ppp_shared->evict_fruitless_active = false;
		ppp_shared->evict_failed_at = 0;

		if (ev)
		{
			ev->evicted = true;
			ev->ghost = (best_class == PPP_CLASS_GHOST);
			strlcpy(ev->rolename, victim->rolename, NAMEDATALEN);
			if (best_class >= PPP_CLASS_LIVE_COUNTER)
				ev->lost_failed_count = victim->failed_count;
			if (best_class != PPP_CLASS_GHOST)
			{
				/* only an expired lock with a stale audit has some here */
				ev->lost_pending_failures = victim->pending_failures;
				ev->lost_lock_audit = victim->lock_pending_audit;
			}
			memcpy(&ev->victim, victim, sizeof(pppRoleEntry));
		}
		hash_search(ppp_role_hash, &victim->key, HASH_REMOVE, NULL);
	}
	else
	{
		/*
		 * No scan: the hash is not full.  A series of fruitless scans
		 * started earlier is over (entries have left since); a later one
		 * starts afresh instead of completing a tour over a hash that has
		 * changed in between.  The pause that followed a complete fruitless
		 * tour (evict_failed_at) is over too: room has been found.
		 */
		ppp_shared->evict_fruitless_active = false;
		ppp_shared->evict_failed_at = 0;
	}

	entry = (pppRoleEntry *) hash_search(ppp_role_hash, key,
										 HASH_ENTER_NULL, &found);
	if (entry && !found)
		ppp_init_entry(entry, rolename);
	return entry;
}

/*
 * Report an eviction made by ppp_enter_role().  Must be called without
 * holding ppp_shared->lock.  Evicting a pseudo-entry or an inactive entry
 * is routine (DEBUG1); losing a live counter or unaudited failures of an
 * existing role is logged.
 */
void
ppp_log_eviction(const pppEviction *ev)
{
	if (ev == NULL || !ev->evicted)
		return;

	if (ev->lost_lock_audit)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "shared memory full: entry of role \"%s\" evicted before its lock was audited (%d counted failures, %d failures not yet audited lost)",
						ev->rolename, ev->lost_failed_count,
						ev->lost_pending_failures),
				 errdetail("The lock has expired, and its role_locked audit row could not be written by the worker for more than %d hours, or the server is a hot standby; that row is lost.",
						   PPP_STALE_AUDIT_SECS / 3600),
				 errhint("Check that the pg_pass_policy worker runs on pg_pass_policy.database, or increase pg_pass_policy.max_tracked_roles.")));
	else if (ev->lost_failed_count > 0 || ev->lost_pending_failures > 0)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "shared memory full: entry of role \"%s\" evicted (%d counted failures, %d failures not yet audited lost)",
						ev->rolename, ev->lost_failed_count,
						ev->lost_pending_failures),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));
	else if (ev->ghost)
		elog(DEBUG1, PPP_LOG_PREFIX "shared memory full: entry of non-existent role \"%s\" evicted",
			 ev->rolename);
	else
		elog(DEBUG1, PPP_LOG_PREFIX "shared memory full: inactive entry of role \"%s\" evicted",
			 ev->rolename);
}

/*
 * Called from the shmem_startup_hook (pg_pass_policy.c), after ppp_shared
 * has been allocated and its LWLock assigned.  The caller holds
 * AddinShmemInitLock.
 *
 * The key is a pppRoleKey (OID, or name of a pseudo-entry), hashed by
 * ppp_key_hash (HASH_FUNCTION).  Without HASH_COMPARE, dynahash compares
 * keys with memcmp() whenever the hash function is not string_hash, and
 * copies them with memcpy() (hash_create(), dynahash.c, unchanged from PG
 * 14 to 17beta1): every key is zeroed before it is filled
 * (ppp_make_key).
 *
 * The hash size must be accounted for in ppp_shmem_size():
 *	 hash_estimate_size(ppp_max_tracked_roles, sizeof(pppRoleEntry)).
 *
 * The fixed shared state (default parameters, first reload request) is
 * initialised by ppp_shmem_startup() only.
 */
void
ppp_lockout_shmem_init(void)
{
	HASHCTL		info;

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pppRoleKey);
	info.entrysize = sizeof(pppRoleEntry);
	info.hash = ppp_key_hash;

	ppp_role_hash = ShmemInitHash("pg_pass_policy roles",
								  ppp_max_tracked_roles,
								  ppp_max_tracked_roles,
								  &info,
								  HASH_ELEM | HASH_FUNCTION);
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
 * Look a user name up in pg_authid: *roleid its OID (InvalidOid when no
 * role has that name), *expired when its rolvaliduntil is in the past,
 * *superuser when it has rolsuper.  The hook runs inside the transaction
 * started by InitPostgres() for authentication, with catalog caches
 * available (see the file header); false is returned, nothing being looked
 * up, if that ever stops being true: the caller then refuses the
 * connection (fail-closed).
 */
static bool
ppp_role_lookup(const char *rolename, TimestampTz now,
				Oid *roleid, bool *expired, bool *superuser)
{
	HeapTuple	tup;
	Datum		datum;
	bool		isnull;

	*roleid = InvalidOid;
	*expired = false;
	*superuser = false;
	if (!IsTransactionState())
		return false;

	tup = SearchSysCache1(AUTHNAME, CStringGetDatum(rolename));
	if (!HeapTupleIsValid(tup))
		return true;
	datum = SysCacheGetAttr(AUTHNAME, tup, Anum_pg_authid_rolvaliduntil,
							&isnull);
	if (!isnull && DatumGetTimestampTz(datum) < now)
		*expired = true;
	*superuser = ((Form_pg_authid) GETSTRUCT(tup))->rolsuper;
	*roleid = ((Form_pg_authid) GETSTRUCT(tup))->oid;
	ReleaseSysCache(tup);
	return true;
}

/*
 * Does the authentication method of the connection compare the client's
 * answer with pg_authid.rolpassword?  These methods (get_role_password() in
 * libpq/crypt.c, PG 13 to 18) also refuse a role whose rolvaliduntil is in
 * the past, whatever the password: such a failure proves nothing about the
 * password and is not counted.  LDAP, PAM, RADIUS and BSD ignore
 * rolvaliduntil.
 */
static bool
ppp_auth_method_checks_valid_until(const Port *port)
{
	if (port->hba == NULL)
		return false;

	switch (port->hba->auth_method)
	{
		case uaPassword:
		case uaMD5:
		case uaSCRAM:
			return true;
		default:
			return false;
	}
}

/*
 * Did the authentication method of the connection check a password or a
 * secret supplied by the client?  Only such failures are guesses worth
 * counting.  The other methods fail without the client having tried any
 * secret for the role: a peer or ident mismatch, a certificate whose name
 * does not match, a GSSAPI/SSPI principal...  Counting them would let
 * anyone allowed to reach the server lock any role by name (ident, for
 * instance, trusts an identd the client may control).  "reject" lines and
 * the implicit reject never reach the hook: ClientAuthentication() raises
 * its FATAL in the switch, before calling it (13.2, 16.4, 17beta1); they
 * are not counted either way.  Methods added later (oauth in PG 18) are
 * not counted until they are reviewed here.
 *
 * port->hba is set by hba_getauthmethod() at the start of
 * ClientAuthentication(), before the hook is called; checked anyway.  The
 * UserAuth values used here exist unchanged in PG 13 to 18 (libpq/hba.h).
 */
static bool
ppp_auth_method_checks_secret(const Port *port)
{
	if (port->hba == NULL)
		return false;

	switch (port->hba->auth_method)
	{
		case uaPassword:
		case uaMD5:
		case uaSCRAM:
		case uaLDAP:
		case uaPAM:
		case uaRADIUS:
		case uaBSD:
			return true;
		default:
			return false;
	}
}

/*
 * Did the connection authenticate with peer (Unix-domain socket only)?  It
 * ties the role to an OS account of the server host, which makes it the
 * emergency administration path of the start-up window, for the superusers
 * of pg_pass_policy.rescue_roles only (SPEC 6.3, "Démarrage").  trust does
 * not qualify, even over a Unix-domain socket: it checks nothing, and any
 * local account allowed on the socket gets any role name.
 */
static bool
ppp_auth_is_peer(const Port *port)
{
	return port->hba != NULL && port->hba->auth_method == uaPeer;
}

/*
 * Has the PPP_RESCUE_LOG_SECS period since logged_at elapsed?  A clock set
 * back (now before logged_at) counts as elapsed: the role would otherwise
 * stay silent until the clock caught up.
 */
static bool
ppp_rescue_period_elapsed(TimestampTz logged_at, TimestampTz now)
{
	return now < logged_at ||
		TimestampDifferenceExceeds(logged_at, now, PPP_RESCUE_LOG_SECS * 1000);
}

/*
 * Rescue admission of a role (see PPP_RESCUE_LOG_SLOTS): true when it must
 * be logged, *suppressed then receiving the number of admissions of that
 * role not logged since its previous LOG.  A role gets a slot at its first
 * admission: a free one, or the slot of another role whose period has
 * elapsed with nothing left to report.  When none is left, the admission is
 * logged anyway (no slot, no limit): a role is never hidden.  Caller holds
 * ppp_shared->lock exclusively.
 */
static bool
ppp_rescue_log_due(const char *rolename, TimestampTz now, int32 *suppressed)
{
	int			i;
	int			free_slot = -1;
	pppRescueLogSlot *slot;

	*suppressed = 0;
	for (i = 0; i < PPP_RESCUE_LOG_SLOTS; i++)
	{
		slot = &ppp_shared->rescue_log[i];
		if (slot->rolename[0] == '\0')
		{
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (strncmp(slot->rolename, rolename, NAMEDATALEN) == 0)
		{
			if (!ppp_rescue_period_elapsed(slot->logged_at, now))
			{
				if (slot->suppressed < PG_INT32_MAX)
					slot->suppressed++;
				return false;
			}
			*suppressed = slot->suppressed;
			slot->suppressed = 0;
			slot->logged_at = now;
			return true;
		}
		if (free_slot < 0 && slot->suppressed == 0 &&
			ppp_rescue_period_elapsed(slot->logged_at, now))
			free_slot = i;
	}
	if (free_slot >= 0)
	{
		slot = &ppp_shared->rescue_log[free_slot];
		strlcpy(slot->rolename, rolename, NAMEDATALEN);
		slot->logged_at = now;
		slot->suppressed = 0;
	}
	return true;
}

/*
 * Worker, at every synchronisation: LOG the rescue admissions that were not
 * logged (suppressed) once the period of their role has elapsed, and all of
 * them once the start-up window is closed (no admission is left unlogged
 * then: none can be added).  logged_at is kept, so that the next admission
 * of the role is logged as usual once its period has elapsed.
 */
void
ppp_flush_rescue_log(void)
{
	pppRescueLogSlot due[PPP_RESCUE_LOG_SLOTS];
	TimestampTz now = GetCurrentTimestamp();
	int			ndue = 0;
	int			i;

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (i = 0; i < PPP_RESCUE_LOG_SLOTS; i++)
	{
		pppRescueLogSlot *slot = &ppp_shared->rescue_log[i];

		if (slot->suppressed > 0 &&
			(ppp_shared->locks_loaded ||
			 ppp_rescue_period_elapsed(slot->logged_at, now)))
		{
			due[ndue++] = *slot;
			slot->suppressed = 0;
		}
	}
	LWLockRelease(ppp_shared->lock);

	for (i = 0; i < ndue; i++)
		ereport(LOG,
				(errmsg_plural(PPP_LOG_PREFIX "%d admission of superuser \"%s\" by peer authentication before the lock state was loaded was not logged",
							   PPP_LOG_PREFIX "%d admissions of superuser \"%s\" by peer authentication before the lock state was loaded were not logged",
							   due[i].suppressed, (int) due[i].suppressed,
							   due[i].rolename),
				 errdetail("The role is listed in pg_pass_policy.rescue_roles; its admissions are logged at most once every %d seconds.",
						   PPP_RESCUE_LOG_SECS)));
}

/*
 * FATAL refusal of a locked role (whatever the status, see
 * ppp_client_auth_hook).  Never returns.
 */
static void
ppp_fatal_locked(const char *rolename, TimestampTz locked_until)
{
	if (locked_until == DT_NOEND)
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("role \"%s\" is locked by pg_pass_policy", rolename),
				 errdetail("The role is locked until manual unlock.")));
	ereport(FATAL,
			(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
			 errmsg("role \"%s\" is locked by pg_pass_policy", rolename),
			 errdetail("The role is locked until %s.",
					   timestamptz_to_str(locked_until))));
}

/*
 * Generic 57P03 refusal of the start-up window, also used when the role
 * cannot be looked up (fail-closed).  No hint: the client is not
 * authenticated and must not learn anything about the configuration, the
 * emergency paths included (rescue_roles, exempt_roles, superusers when the
 * worker is missing).  The administrator finds them in the hint of the LOG
 * of the caller and in the documentation (SPEC 12).  Never returns.
 */
static void
ppp_fatal_not_loaded(void)
{
	ereport(FATAL,
			(errcode(ERRCODE_CANNOT_CONNECT_NOW),
			 errmsg(PPP_LOG_PREFIX "lock state not loaded yet, retry"),
			 errdetail("The server has just started; retry in a few seconds.")));
}

/*
 * ClientAuthentication_hook: see SPEC 6.3.
 *
 * - the entry of the connection is that of the OID of the role, looked up
 *   by name in pg_authid before any LWLock is taken (ppp_role_lookup); a
 *   name that matches no role has a pseudo-entry, keyed by the name.  A
 *   rename keeps the entry of the role, a role created under the name of a
 *   dropped one, or of a name tried earlier, gets its own;
 * - a locked role is refused with FATAL whatever the authentication result
 *   and the method, so that a correct password cannot be told apart from a
 *   wrong one while the role is locked;
 * - STATUS_ERROR of a method that checks a password or a secret
 *   (ppp_auth_method_checks_secret) is counted as a failure, for existing
 *   and non-existent user names alike: a non-existent name is "locked"
 *   after max_failures failures too, so that the answer does not reveal
 *   whether the role exists (like the mock SCRAM exchange of PostgreSQL).
 *   Its pseudo-entry is always evictable (PPP_CLASS_GHOST);
 * - STATUS_EOF (client closed the connection when asked for a password, as
 *   psql does before prompting) is NOT counted: no password was tried;
 * - STATUS_ERROR of a password method (ppp_auth_method_checks_valid_until)
 *   for a role whose rolvaliduntil is in the past is NOT counted either:
 *   PostgreSQL refuses it even with the right password, so counting would
 *   lock an expired role whose owner keeps typing the right password (and
 *   the connection is refused anyway).  The refusal of a locked role still
 *   applies;
 * - until the worker has loaded the persisted locks after the shared memory
 *   initialisation (ppp_shared->locks_loaded), every non-exempt role is
 *   refused with FATAL 57P03 "lock state not loaded yet", whatever the
 *   authentication method (trust, peer, cert... included: a role locked in
 *   role_state is not known yet) and the status, and failures are not
 *   counted (the answer is "retry" whatever the password).  Superusers are
 *   refused that way too, with two exceptions: the worker is demonstrably
 *   missing (no PID published PPP_WORKER_MISSING_GRACE_SECS after the
 *   shared memory initialisation): they then get the real answer and their
 *   failures are counted, so that an installation whose worker never starts
 *   can still be administered; or they are listed in
 *   pg_pass_policy.rescue_roles and authenticated successfully by peer
 *   (ppp_auth_is_peer), the emergency path when the window stays closed
 *   (worker running but unable to load the locks).  A lock present in shared
 *   memory still applies to them (SPEC 6.3, "Démarrage").
 *
 * The usual connection (success of a role without state, no start-up
 * window) takes the LWLock once, shared.
 */
static void
ppp_client_auth_hook(Port *port, int status)
{
	const char *rolename;
	TimestampTz now;
	TimestampTz locked_until = 0;
	bool		refuse = false;
	bool		not_loaded = false;
	bool		log_not_loaded = false;
	bool		log_worker_missing = false;
	bool		log_rescue = false;
	int32		rescue_suppressed = 0;
	bool		check_window;
	bool		worker_missing = false;
	bool		local_admin = false;
	bool		is_superuser = false;
	bool		just_locked = false;
	bool		hash_full = false;
	bool		expired = false;
	bool		count_failure;
	bool		in_recovery;
	int			failed_count = 0;
	Oid			roleid;
	pppRoleKey	key;
	pppRoleEntry *entry;
	pppEviction ev;

	rolename = port ? port->user_name : NULL;

	if (!ppp_enabled || ppp_shared == NULL || ppp_role_hash == NULL ||
		rolename == NULL || rolename[0] == '\0' ||
		ppp_role_is_exempt(rolename))
	{
		if (prev_client_auth_hook)
			prev_client_auth_hook(port, status);
		return;
	}

	count_failure = (status == STATUS_ERROR &&
					 ppp_auth_method_checks_secret(port));

	now = GetCurrentTimestamp();

	/*
	 * Start-up window still open?  Read without the lock: locks_loaded only
	 * goes from false to true (the shared memory initialisation, which sets
	 * it back to false, restarts every backend), so "loaded" here is final;
	 * "not loaded" is checked again under the lock below.  Every method is
	 * concerned, those that check no secret (trust, peer, cert, gss, sspi...)
	 * included: a role locked in role_state must stay out whatever the line
	 * of pg_hba.conf it matches.
	 */
	check_window = !ppp_shared->locks_loaded;

	/*
	 * Catalog lookup, at every connection and before taking the LWLock (no
	 * catalog access under an LWLock): it gives the key of the entry (the
	 * OID; a pseudo-key for a name without role), the expiry of the role and
	 * whether it is a superuser.  The key does not depend on the state of
	 * the entry, so the lookup is never made again below.  Outside a
	 * transaction (never seen: see the file header), the role cannot be
	 * looked up: the connection is refused (fail-closed) rather than let
	 * through without its lock state.
	 */
	if (!ppp_role_lookup(rolename, now, &roleid, &expired, &is_superuser))
	{
		if (prev_client_auth_hook)
			prev_client_auth_hook(port, status);
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "authentication hook called outside a transaction: connection of role \"%s\" refused",
						rolename),
				 errdetail("The role cannot be looked up in pg_authid, so its lock state is unknown; the connection is refused (fail-closed).")));
		ppp_fatal_not_loaded();
		return;
	}
	ppp_make_key(&key, roleid, rolename);
	if (count_failure && expired && ppp_auth_method_checks_valid_until(port))
		count_failure = false;
	in_recovery = RecoveryInProgress();

	/*
	 * Fast path: nothing to count and the start-up window closed.  A shared
	 * lock is enough to find whether the entry is locked; the exclusive lock
	 * is only needed by a success that resets a live counter.
	 */
	if (!count_failure && !check_window)
	{
		bool		write_needed = false;

		LWLockAcquire(ppp_shared->lock, LW_SHARED);
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND,
											 NULL);
		if (entry != NULL)
		{
			if (ppp_is_locked(entry, now))
			{
				refuse = true;
				locked_until = entry->locked_until;
			}
			else if (status == STATUS_OK && entry->failed_count > 0)
				write_needed = true;
		}
		LWLockRelease(ppp_shared->lock);

		if (!write_needed)
		{
			/* the previous hook still sees the attempt (see below) */
			if (prev_client_auth_hook)
				prev_client_auth_hook(port, status);
			if (refuse)
				ppp_fatal_locked(rolename, locked_until);
			return;
		}
	}

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);

	/*
	 * Fail-closed start-up window: until the worker has re-injected the
	 * persisted locks, a role locked in role_state (manual "infinity" lock
	 * of a compromised account included) is not known here.  Every
	 * authentication method is refused whatever the status (after the
	 * refusal of a lock already in shared memory, below): the methods that
	 * check no secret (trust, peer, cert...) would otherwise let a role
	 * locked in role_state in, and for the others the answer does not tell
	 * a right password from a wrong one; such a failure is not
	 * counted either, since the client is told to retry whatever the
	 * password it sent, and a success does not reset the counter (see
	 * below).  The exempt roles (above) never reach this point.
	 *
	 * Superusers are refused the same way during a normal start-up (worker
	 * running, reload in progress or failing): a superuser locked by hand in
	 * role_state stays out, and the answer does not tell a superuser name
	 * from another one.  They are let through (real answer, failures
	 * counted) only when no worker has published its PID long after the
	 * shared memory was initialised: it was probably never started
	 * (max_worker_processes exhausted: RegisterBackgroundWorker() does not
	 * report it) or cannot connect (pg_pass_policy.database does not
	 * exist).  With exempt_roles empty, such an installation would otherwise
	 * lock every password login out, postgres included.  That situation is
	 * logged at most once per PPP_WORKER_MISSING_LOG_SECS for the whole
	 * instance.
	 *
	 * A superuser listed in pg_pass_policy.rescue_roles that authenticated
	 * successfully by peer is let through whatever the worker state: the
	 * window may stay closed indefinitely with a worker running (reload
	 * failing: extension not trusted, hash full...), and that local access
	 * is then the only way left to administer the instance besides
	 * exempt_roles.  A lock of role_state is not known here (no catalog
	 * access but the syscache), so the access cannot depend on it: it is
	 * restricted instead to roles the administrator listed on purpose
	 * (empty by default: no rescue access) and to peer, which ties the role
	 * to an OS account of the server host (trust checks nothing, even over
	 * a Unix-domain socket).  A failed peer check (status not OK) keeps the
	 * 57P03 answer, so that it does not tell a superuser name from another
	 * one.
	 */
	if (check_window && !ppp_shared->locks_loaded)
	{
		worker_missing = (ppp_get_worker_pid() == 0 &&
						  TimestampDifferenceExceeds(ppp_shared->shmem_init_at, now,
													 PPP_WORKER_MISSING_GRACE_SECS * 1000));
		local_admin = (is_superuser && status == STATUS_OK &&
					   ppp_auth_is_peer(port) &&
					   ppp_role_is_rescue(rolename));
		if (!(is_superuser && worker_missing) && !local_admin)
		{
			not_loaded = true;
			count_failure = false;
		}
		if (worker_missing)
			log_worker_missing = ppp_log_due(&ppp_shared->worker_missing_logged_at,
											 now,
											 PPP_WORKER_MISSING_LOG_SECS * 1000);
	}

	memset(&ev, 0, sizeof(ev));
	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry == NULL && count_failure)
	{
		/*
		 * A plain counting entry: when the hash is full it only evicts
		 * pseudo-entries, then inactive entries.
		 */
		entry = ppp_enter_role(&key, rolename, PPP_ENTER_COUNT, now,
							   in_recovery, &ev);
		if (entry == NULL)
			hash_full = !ev.scan_skipped;
	}

	/*
	 * The key is the identity of the role: a lock of the entry is the lock
	 * of the role that connects, no membership test is needed.  A lock
	 * already in shared memory wins over the start-up window.
	 */
	if (entry != NULL && ppp_is_locked(entry, now))
	{
		refuse = true;
		locked_until = entry->locked_until;
		not_loaded = false;
	}

	/*
	 * During the start-up window (not_loaded), the entry is left strictly
	 * unchanged: neither a failure counted nor a counter reset by a success.
	 * A reset would be an oracle: four wrong passwords, a candidate, then a
	 * wrong one would end in "locked" after the window only if the candidate
	 * were wrong.
	 */
	if (entry != NULL && !not_loaded && !refuse)
	{
		/* current name of the role, for the messages of the worker */
		if (OidIsValid(key.roleid))
			strlcpy(entry->rolename, rolename, NAMEDATALEN);

		/* expired lock, if any (ppp_sync_cleanup does the same) */
		(void) ppp_expire_lock(entry, now, false);

		if (status == STATUS_OK)
		{
			entry->failed_count = 0;
			entry->first_failure_at = 0;
		}
		else if (count_failure)
		{
			/* restart counting when the window has elapsed */
			if (entry->failed_count == 0 ||
				entry->first_failure_at == 0 ||
				ppp_window_elapsed(entry, now))
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
				/*
				 * A previous automatic lock whose role_locked row has not
				 * been written yet (worker late, standby) is overwritten:
				 * audit_lock_seq numbers the episodes, so that the worker
				 * reports how many were not audited one by one (SPEC 6.3).
				 */
				if (!entry->lock_pending_audit)
					entry->audit_acked_seq = entry->audit_lock_seq;
				entry->audit_lock_seq++;
				entry->lock_pending_audit = true;
				entry->audit_locked_until = entry->locked_until;
				entry->audit_lock_set_at = now;
				entry->lock_set_at = now;
				entry->lock_from_state = false;
				just_locked = true;
				locked_until = entry->locked_until;
				failed_count = entry->failed_count;
			}
		}
	}

	if (not_loaded)
		log_not_loaded = ppp_log_due(&ppp_shared->not_loaded_logged_at, now,
									 1000);
	else if (local_admin && !refuse)
	{
		/*
		 * Rescue admissions are logged with the role name, once per role and
		 * per PPP_RESCUE_LOG_SECS: the next LOG of that role (or the worker,
		 * ppp_flush_rescue_log) tells how many were not logged meanwhile, so
		 * that a script connecting in a loop does not flood the server log
		 * while no role is ever hidden (a limit for the whole instance would
		 * hide the other roles; when the table of roles is full, the
		 * admission is logged anyway).
		 */
		log_rescue = ppp_rescue_log_due(rolename, now, &rescue_suppressed);
	}

	LWLockRelease(ppp_shared->lock);

	/*
	 * Every message of this hook is LOG (server log only), except the FATAL
	 * refusals below: they must not tell an unauthenticated client anything
	 * about the internal state.  PostgreSQL itself only sends ERROR and
	 * above to the client during authentication (ClientAuthInProgress), but
	 * a WARNING would reach it should that ever change.
	 */
	ppp_log_eviction(&ev);
	if (log_worker_missing)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "worker has not loaded the lock state yet (worker_pid = 0)"),
				 errdetail("No pg_pass_policy background worker is running %d seconds after the shared memory initialisation; roles not listed in pg_pass_policy.exempt_roles are refused meanwhile, whatever the authentication method (at most one message per minute).",
						   PPP_WORKER_MISSING_GRACE_SECS),
				 errhint("Check max_worker_processes and pg_pass_policy.database; superusers and roles listed in pg_pass_policy.exempt_roles can still connect.")));
	if (log_rescue)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "superuser \"%s\" admitted by peer authentication before the lock state is loaded",
						rolename),
				 rescue_suppressed > 0 ?
				 errdetail_plural("The role is listed in pg_pass_policy.rescue_roles; a lock it may hold in role_state is not known yet. %d earlier admission of this role was not logged (at most one message per role every %d seconds).",
								  "The role is listed in pg_pass_policy.rescue_roles; a lock it may hold in role_state is not known yet. %d earlier admissions of this role were not logged (at most one message per role every %d seconds).",
								  rescue_suppressed, (int) rescue_suppressed,
								  PPP_RESCUE_LOG_SECS) :
				 errdetail("The role is listed in pg_pass_policy.rescue_roles; a lock it may hold in role_state is not known yet (at most one message per role every %d seconds).",
						   PPP_RESCUE_LOG_SECS)));
	if (hash_full)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "cannot track authentication failures of role \"%s\": too many tracked roles",
						rolename),
				 errdetail("All %d shared memory entries hold active locks, profile parameters or live failure counters of existing roles; failures are not counted for the next second.",
						   ppp_max_tracked_roles),
				 errhint("Increase pg_pass_policy.max_tracked_roles.")));

	if (just_locked && ppp_log_events)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "role \"%s\" locked after %d failed attempts",
						rolename, failed_count)));

	/*
	 * Chain to the previous hook before refusing a locked role: a module
	 * loaded before us (auth_delay, a login audit...) still sees the
	 * attempt with its real status.  It may raise its own FATAL first.
	 */
	if (prev_client_auth_hook)
		prev_client_auth_hook(port, status);

	if (refuse)
		ppp_fatal_locked(rolename, locked_until);

	if (not_loaded)
	{
		if (log_not_loaded)
			ereport(LOG,
					(errmsg(PPP_LOG_PREFIX "refusing connections until the background worker has loaded the lock state"),
					 errdetail("Roles not listed in pg_pass_policy.exempt_roles are refused, whatever the authentication method, until the persisted locks are re-injected from role_state (at most one message per second)."),
					 errhint("Check that the pg_pass_policy background worker is running (pass_policy.worker_status()). Meanwhile, roles listed in pg_pass_policy.exempt_roles can connect, superusers listed in pg_pass_policy.rescue_roles through peer authentication only, and any superuser once no worker has published its PID %d seconds after the shared memory initialisation.",
							 PPP_WORKER_MISSING_GRACE_SECS)));
		ppp_fatal_not_loaded();
	}
}

/* ------------------------------------------------------------------------
 * SQL-callable functions
 * ------------------------------------------------------------------------
 */

/* ------------------------------------------------------------------------
 * Deferred shared memory writes (applied at PRE_COMMIT / COMMIT)
 * ------------------------------------------------------------------------
 */
typedef enum pppShmemOp
{
	PPP_OP_LOCK,
	PPP_OP_UNLOCK,
	PPP_OP_RESET
} pppShmemOp;

typedef struct pppPendingOp
{
	pppShmemOp	op;
	pppRoleKey	key;			/* PPP_OP_LOCK: always the OID of a role
								 * that existed when it was requested */
	char		dispname[NAMEDATALEN];	/* name for messages */
	TimestampTz until;			/* PPP_OP_LOCK only */
	TimestampTz queued_at;		/* when it was requested */
	bool		expired_only;	/* PPP_OP_UNLOCK: lift an expired lock only */
	bool		kept_newer;		/* PPP_OP_UNLOCK: a newer lock was kept */
	SubTransactionId subxid;	/* sub-transaction that requested it */

	/* PPP_OP_LOCK applied at PRE_COMMIT (ppp_apply_lock_ops) */
	bool		applied;
	bool		prev_existed;	/* entry existed before the lock */
	pppRoleEntry prev;			/* its previous content (undo on ERROR) */
	pppEviction ev;				/* eviction made to create it */

	struct pppPendingOp *next;
} pppPendingOp;

/* list of the current transaction, allocated in TopTransactionContext */
static pppPendingOp *ppp_pending_ops = NULL;
static pppPendingOp *ppp_pending_ops_tail = NULL;

/* the list holds at least one PPP_OP_LOCK (set at PRE_COMMIT) */
static bool ppp_xact_has_lock_ops = false;

/*
 * shmem_reload() was called in the current transaction: sub-transaction
 * that owns the request, InvalidSubTransactionId if none.  Like the
 * subxid of a pppPendingOp, it is handed to the parent when the
 * sub-transaction commits and the request is dropped when it aborts.  It is
 * always the current sub-transaction or one of its ancestors: the request
 * of a committed child moves up to the parent, the one of an aborted child
 * is dropped.  A second call therefore keeps the owner already recorded.
 */
static SubTransactionId ppp_reload_subxid = InvalidSubTransactionId;

/*
 * Last role whose password change the password hook recorded
 * (record_password_change()) in the current transaction, read by
 * pass_policy._record_done(); ppp_recorded_subxid is the sub-transaction
 * that owns it (handed to the parent at sub-commit, dropped at sub-abort,
 * like ppp_reload_subxid), InvalidSubTransactionId if none.  Cleared at
 * COMMIT, ABORT and PREPARE.
 */
static char ppp_recorded_role[NAMEDATALEN];
static SubTransactionId ppp_recorded_subxid = InvalidSubTransactionId;

/* callbacks registered once per backend */
static bool ppp_xact_cb_registered = false;

/*
 * Set reload_requested and wake the worker up (SIGHUP = reload the
 * configuration and run a cycle now).  Not signalled when called from the
 * worker itself (run_maintenance() calls shmem_reload()), which would
 * otherwise loop forever.  Runs after COMMIT: never raises an ERROR.
 */
static void
ppp_signal_worker_reload(void)
{
	pid_t		pid;

	if (ppp_shared == NULL)
		return;

	pg_atomic_write_u32(&ppp_shared->reload_requested, 1);

	pid = ppp_get_worker_pid();

	if (pid > 0 && pid != MyProcPid)
	{
		if (kill(pid, SIGHUP) != 0)
			ereport(DEBUG1,
					(errmsg(PPP_LOG_PREFIX "could not signal worker process %d: %m",
							(int) pid)));
	}
}

/*
 * Is an operation overridden by a later operation of the opposite kind on
 * the same role (a lock followed by an unlock, or the reverse)?  The lock
 * and the unlock are not applied at the same point of the commit, so the
 * order of the list must be resolved beforehand.
 */
static bool
ppp_op_overridden(const pppPendingOp *op)
{
	const pppPendingOp *o;
	pppShmemOp	opposite = (op->op == PPP_OP_LOCK) ? PPP_OP_UNLOCK : PPP_OP_LOCK;

	for (o = op->next; o != NULL; o = o->next)
		if (o->op == opposite &&
			memcmp(&o->key, &op->key, sizeof(pppRoleKey)) == 0)
			return true;
	return false;
}

/*
 * XACT_EVENT_PRE_COMMIT: apply every PPP_OP_LOCK of the transaction, in
 * PPP_ENTER_PRIORITY mode, under one exclusive hold of the lock.  If one of
 * them finds no room (every entry is PPP_CLASS_KEEP), the locks already
 * applied by this call are undone and an ERROR is raised: the transaction
 * aborts (role_state update and audit row included), lock_role() fails
 * visibly and nothing claims a lock that is not enforced (fail-closed).
 * The undo restores the shared memory exactly: entries that existed get
 * their previous content back, entries created are removed and the entries
 * they evicted (a failure counter, failures not yet audited) are put back,
 * in reverse order, so that a failed lock_role() costs nobody a counter.
 *
 * Applying the locks here rather than at COMMIT means that no other
 * insertion (the authentication hook, another lock_role(), a worker reload)
 * can take the room between the check and the write.  The lock may then
 * be enforced a little before the transaction is visible, which is harmless;
 * if the transaction fails after PRE_COMMIT, the lock stays in shared
 * memory without a role_state row (fail-closed): unlock_role() lifts it,
 * and so does the next worker reload on a primary (lock_from_state, see
 * ppp_finish_lock_ops).  The entry is marked lock_inflight until COMMIT or
 * ABORT, so that a worker reload whose snapshot predates the commit does
 * not lift it.
 *
 * Nothing is done (and the lock is not taken) when the transaction queued
 * no PPP_OP_LOCK.
 */
static void
ppp_apply_lock_ops(void)
{
	pppPendingOp *op;
	pppPendingOp **ops;
	int			nops = 0;
	int			i;
	TimestampTz now;
	bool		in_recovery;
	const char *missing = NULL;

	ppp_xact_has_lock_ops = false;
	if (ppp_pending_ops == NULL || ppp_shared == NULL || ppp_role_hash == NULL)
		return;

	for (op = ppp_pending_ops; op != NULL; op = op->next)
		if (op->op == PPP_OP_LOCK)
			nops++;
	if (nops == 0)
		return;
	ppp_xact_has_lock_ops = true;

	ops = (pppPendingOp **) palloc(sizeof(pppPendingOp *) * nops);
	nops = 0;
	for (op = ppp_pending_ops; op != NULL; op = op->next)
		if (op->op == PPP_OP_LOCK && !ppp_op_overridden(op))
		{
			/*
			 * op->key is the OID of the role, looked up when the lock was
			 * requested: a rename later in this transaction keeps the
			 * entry, a DROP ROLE leaves an entry for an OID that no longer
			 * exists, which the worker removes (ppp_sync_cleanup); no
			 * ERROR at commit
			 */
			ops[nops++] = op;
		}

	now = GetCurrentTimestamp();
	in_recovery = RecoveryInProgress();

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (i = 0; i < nops; i++)
	{
		pppRoleEntry *entry;

		op = ops[i];
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &op->key,
											 HASH_FIND, NULL);
		op->prev_existed = (entry != NULL);
		if (entry != NULL)
			memcpy(&op->prev, entry, sizeof(pppRoleEntry));
		else
			entry = ppp_enter_role(&op->key, op->dispname, PPP_ENTER_PRIORITY,
								   now, in_recovery, &op->ev);
		if (entry == NULL)
		{
			missing = op->dispname;
			break;
		}

		/*
		 * The SQL caller writes its own audit row.  lock_pending_audit is
		 * left alone: an automatic lock not yet audited keeps its pending
		 * role_locked row (audit_locked_until), which the worker writes
		 * without copying it to role_state (locked_until differs now).
		 */
		strlcpy(entry->rolename, op->dispname, NAMEDATALEN);
		entry->locked_until = op->until;
		entry->lock_set_at = now;

		/*
		 * Mirrored in role_state by lock_role(): a later reload lifts it if
		 * the row says otherwise.  Not on a standby, where shmem_lock_role()
		 * is the only way to lock a role locally (nothing can be written in
		 * role_state there): such a lock must survive the reloads.
		 */
		entry->lock_from_state = !in_recovery;
		entry->lock_inflight++;
		op->applied = true;
	}

	if (missing != NULL)
	{
		/*
		 * Undo, in reverse order: we still hold the lock, nobody else saw
		 * the intermediate states.  Removing the entry created by an
		 * operation frees the room its eviction made, so the victim can
		 * always be entered again (HASH_ENTER_NULL does not fail there);
		 * the reverse order also handles a later operation that evicted or
		 * recreated the entry of an earlier one.
		 */
		while (--i >= 0)
		{
			pppRoleEntry *entry;

			op = ops[i];
			if (op->prev_existed)
			{
				entry = (pppRoleEntry *) hash_search(ppp_role_hash, &op->key,
													 HASH_FIND, NULL);
				if (entry != NULL)
					memcpy(entry, &op->prev, sizeof(pppRoleEntry));
			}
			else
			{
				hash_search(ppp_role_hash, &op->key, HASH_REMOVE, NULL);
				if (op->ev.evicted)
				{
					bool		found;

					entry = (pppRoleEntry *) hash_search(ppp_role_hash,
														 &op->ev.victim.key,
														 HASH_ENTER_NULL,
														 &found);
					if (entry != NULL && !found)
						memcpy(entry, &op->ev.victim, sizeof(pppRoleEntry));
					/* restored: nothing was lost, nothing to log */
					op->ev.evicted = (entry == NULL || found);
				}
			}
			op->applied = false;
		}
	}
	LWLockRelease(ppp_shared->lock);

	for (op = ppp_pending_ops; op != NULL; op = op->next)
		if (op->op == PPP_OP_LOCK)
			ppp_log_eviction(&op->ev);

	if (missing != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIGURATION_LIMIT_EXCEEDED),
				 errmsg("cannot lock role \"%s\": pg_pass_policy shared memory is full",
						missing),
				 errdetail("All %d entries of pg_pass_policy.max_tracked_roles hold active locks, locks not yet audited or profile parameters of existing roles; none can be evicted.",
						   ppp_max_tracked_roles),
				 errhint("Increase pg_pass_policy.max_tracked_roles (requires a restart).")));

	pfree(ops);
}

/*
 * Bump ppp_shared->lock_seq and stamp an entry with it.  Caller holds the
 * lock exclusively.
 */
static inline void
ppp_stamp_entry(pppRoleEntry *entry)
{
	entry->lock_seq = ++ppp_shared->lock_seq;
}

/*
 * May a PPP_OP_UNLOCK lift the current lock of an entry?
 *
 * - expired_only (step f of run_maintenance(), which lifts the locks that
 *   have expired in role_state): never an active lock.  The authentication
 *   hook may have set a new automatic lock after the old one expired,
 *   before or during the maintenance transaction: role_state does not
 *   know it yet (the worker copies it at its next cycle).  An expired lock
 *   is not lifted here but handed to ppp_expire_lock() by the caller;
 * - otherwise (unlock_role()): a lock mirrored in role_state
 *   (lock_from_state) is lifted, the role_state row lock orders the unlock
 *   and any lock_role() of the same role; an automatic lock of the hook is
 *   lifted only if it was set before the unlock was requested (lock_set_at
 *   <= queued_at): a lock set by new failures between the UPDATE of
 *   role_state and the COMMIT was not seen by the caller and is kept.
 */
static bool
ppp_unlock_allowed(const pppPendingOp *op, const pppRoleEntry *entry,
				   TimestampTz now)
{
	if (op->expired_only)
		return !ppp_is_locked(entry, now);
	if (!ppp_is_locked(entry, now))
		return true;
	return entry->lock_from_state || entry->lock_set_at <= op->queued_at;
}

/*
 * XACT_EVENT_COMMIT or XACT_EVENT_ABORT: the locks applied at PRE_COMMIT
 * are no longer in flight.  After a COMMIT their role_state rows are
 * visible to any snapshot taken from now on; after an ABORT there is no
 * row, and the next worker reload lifts the lock (lock_from_state).  Then,
 * at COMMIT only, apply the unlocks (see ppp_unlock_allowed) and counter
 * resets, in order.  Runs after the transaction has ended: nothing here may
 * raise an ERROR.
 */
static void
ppp_finish_pending_ops(bool commit)
{
	pppPendingOp *op;
	TimestampTz now;
	bool		kept = false;

	if (ppp_pending_ops == NULL || ppp_shared == NULL || ppp_role_hash == NULL)
		return;
	if (!commit && !ppp_xact_has_lock_ops)
		return;

	now = GetCurrentTimestamp();

	LWLockAcquire(ppp_shared->lock, LW_EXCLUSIVE);
	for (op = ppp_pending_ops; op != NULL; op = op->next)
	{
		pppRoleEntry *entry;

		if (op->op == PPP_OP_LOCK && !op->applied)
			continue;
		if (op->op != PPP_OP_LOCK && !commit)
			continue;
		/* an unlock followed by a lock of the same role: the lock wins */
		if (op->op == PPP_OP_UNLOCK && ppp_xact_has_lock_ops &&
			ppp_op_overridden(op))
			continue;

		entry = (pppRoleEntry *) hash_search(ppp_role_hash, &op->key,
											 HASH_FIND, NULL);
		if (entry == NULL)
			continue;

		switch (op->op)
		{
			case PPP_OP_LOCK:
				if (entry->lock_inflight > 0)
					entry->lock_inflight--;
				ppp_stamp_entry(entry);
				break;
			case PPP_OP_UNLOCK:
				if (!ppp_unlock_allowed(op, entry, now))
				{
					op->kept_newer = true;
					kept = true;
					break;
				}

				/*
				 * expired_only: the lock has expired; it may be a newer
				 * automatic lock than the one role_state held, expired too
				 * but still waiting for its role_locked row
				 * (lock_pending_audit).  ppp_expire_lock() keeps
				 * locked_until in that case, for the worker to audit it
				 * (lifted_before_audit would be wrong) and clear it once
				 * the row is written; it also resets the counters of the
				 * episode that led to the lock, as when the hook or the
				 * worker meets the expired lock first.
				 */
				if (op->expired_only)
				{
					if (ppp_expire_lock(entry, now, true))
						ppp_stamp_entry(entry);
					break;
				}

				/*
				 * lock_pending_audit is kept: an automatic lock lifted
				 * before the worker has written its role_locked row is
				 * still audited (audit_locked_until), and not copied to
				 * role_state since locked_until no longer matches.
				 */
				entry->locked_until = 0;
				entry->lock_from_state = false;
				ppp_stamp_entry(entry);
				break;
			case PPP_OP_RESET:
				entry->failed_count = 0;
				entry->first_failure_at = 0;
				entry->last_failure_at = 0;
				break;
		}
	}
	LWLockRelease(ppp_shared->lock);

	if (kept)
		for (op = ppp_pending_ops; op != NULL; op = op->next)
			if (op->kept_newer)
				ereport(LOG,
						(errmsg(PPP_LOG_PREFIX "unlock of role \"%s\" not applied in shared memory: the role holds a newer lock",
								op->dispname),
						 op->expired_only ?
						 errdetail("Only an expired lock was to be lifted; the active automatic lock set by new failures is kept, and copied to role_state by the worker.") :
						 errdetail("An automatic lock set after the unlock was requested is kept, and copied to role_state by the worker.")));
}

static void
ppp_reset_pending_ops(void)
{
	/* memory goes away with TopTransactionContext */
	ppp_pending_ops = NULL;
	ppp_pending_ops_tail = NULL;
	ppp_xact_has_lock_ops = false;
}

static void
ppp_xact_callback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
		case XACT_EVENT_PARALLEL_PRE_COMMIT:
			/* last point where an ERROR still aborts the transaction */
			ppp_apply_lock_ops();
			break;

		case XACT_EVENT_COMMIT:
		case XACT_EVENT_PARALLEL_COMMIT:
			ppp_recorded_subxid = InvalidSubTransactionId;
			/* after ProcArrayEndTransaction: our rows are visible to the worker */
			ppp_finish_pending_ops(true);
			ppp_reset_pending_ops();
			if (ppp_reload_subxid != InvalidSubTransactionId)
			{
				ppp_reload_subxid = InvalidSubTransactionId;
				ppp_signal_worker_reload();
			}
			break;

		case XACT_EVENT_ABORT:
		case XACT_EVENT_PARALLEL_ABORT:
			ppp_recorded_subxid = InvalidSubTransactionId;
			/* locks applied at PRE_COMMIT, if the commit failed afterwards */
			ppp_finish_pending_ops(false);
			ppp_reset_pending_ops();
			ppp_reload_subxid = InvalidSubTransactionId;
			break;

		case XACT_EVENT_PRE_PREPARE:
			/*
			 * Raised here (as postgres_fdw does) rather than at PREPARE,
			 * which runs after the transaction has been prepared.  The
			 * COMMIT PREPARED may come from another backend: the shared
			 * memory could not be updated then.
			 */
			if (ppp_pending_ops != NULL)
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("cannot PREPARE a transaction that has pending pg_pass_policy shared memory updates")));
			break;

		case XACT_EVENT_PREPARE:
			ppp_recorded_subxid = InvalidSubTransactionId;
			/* a reload request is simply dropped: the next run_maintenance() catches up */
			ppp_reload_subxid = InvalidSubTransactionId;
			break;

		default:
			break;
	}
}

static void
ppp_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
					 SubTransactionId parentSubid, void *arg)
{
	pppPendingOp *op;

	/* the recorded password change, if this sub-transaction owns it */
	if (ppp_recorded_subxid == mySubid)
	{
		if (event == SUBXACT_EVENT_COMMIT_SUB)
			ppp_recorded_subxid = parentSubid;
		else if (event == SUBXACT_EVENT_ABORT_SUB)
			ppp_recorded_subxid = InvalidSubTransactionId;
	}

	/* the reload request, if this sub-transaction owns it */
	if (ppp_reload_subxid == mySubid)
	{
		if (event == SUBXACT_EVENT_COMMIT_SUB)
			ppp_reload_subxid = parentSubid;
		else if (event == SUBXACT_EVENT_ABORT_SUB)
			ppp_reload_subxid = InvalidSubTransactionId;
	}

	if (ppp_pending_ops == NULL)
		return;

	switch (event)
	{
		case SUBXACT_EVENT_COMMIT_SUB:
			/* the parent now owns the requests of this sub-transaction */
			for (op = ppp_pending_ops; op != NULL; op = op->next)
				if (op->subxid == mySubid)
					op->subxid = parentSubid;
			break;

		case SUBXACT_EVENT_ABORT_SUB:
			{
				/*
				 * Drop the requests of this sub-transaction.  Its children
				 * have already been aborted (their requests removed) or
				 * committed (their requests reassigned to mySubid).
				 */
				pppPendingOp *prev = NULL;
				pppPendingOp *next;

				ppp_pending_ops_tail = NULL;
				for (op = ppp_pending_ops; op != NULL; op = next)
				{
					next = op->next;
					if (op->subxid == mySubid)
					{
						if (prev)
							prev->next = next;
						else
							ppp_pending_ops = next;
					}
					else
					{
						prev = op;
						ppp_pending_ops_tail = op;
					}
				}
			}
			break;

		default:
			break;
	}
}

static void
ppp_register_xact_callbacks(void)
{
	if (!ppp_xact_cb_registered)
	{
		RegisterXactCallback(ppp_xact_callback, NULL);
		RegisterSubXactCallback(ppp_subxact_callback, NULL);
		ppp_xact_cb_registered = true;
	}
}

/*
 * Called by the password hook once record_password_change() has returned:
 * the change of rolename is recorded in the current (sub-)transaction.
 */
void
ppp_note_password_recorded(const char *rolename)
{
	ppp_register_xact_callbacks();
	strlcpy(ppp_recorded_role, rolename, NAMEDATALEN);
	ppp_recorded_subxid = GetCurrentSubTransactionId();
}

/*
 * Did the password hook record a change of rolename in the current
 * transaction (and in no sub-transaction rolled back since)?
 */
bool
ppp_password_recorded(const char *rolename)
{
	return ppp_recorded_subxid != InvalidSubTransactionId &&
		strncmp(ppp_recorded_role, rolename, NAMEDATALEN) == 0;
}

/* Queue a write for the end of the current (sub-)transaction. */
static void
ppp_defer_op(pppShmemOp opcode, const pppRoleKey *key, const char *dispname,
			 TimestampTz until, bool expired_only)
{
	pppPendingOp *op;

	ppp_register_xact_callbacks();

	op = (pppPendingOp *) MemoryContextAlloc(TopTransactionContext, sizeof(pppPendingOp));
	op->op = opcode;
	memcpy(&op->key, key, sizeof(pppRoleKey));
	strlcpy(op->dispname, dispname, NAMEDATALEN);
	op->until = until;
	op->queued_at = GetCurrentTimestamp();
	op->expired_only = expired_only;
	op->kept_newer = false;
	op->subxid = GetCurrentSubTransactionId();
	op->applied = false;
	op->prev_existed = false;
	memset(&op->ev, 0, sizeof(pppEviction));
	op->next = NULL;

	if (ppp_pending_ops_tail != NULL)
		ppp_pending_ops_tail->next = op;
	else
		ppp_pending_ops = op;
	ppp_pending_ops_tail = op;
}

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

/*
 * Allocate, in cxt, room for one row of rowsize bytes per entry of
 * ppp_role_hash, then take ppp_shared->lock in the given mode and return
 * with it held: the caller copies the entries under the lock without
 * allocating.  The size is read under a shared lock, plus a small margin
 * for entries created before the lock is taken again; if the hash has grown
 * beyond it meanwhile, the allocation is made again.  *maxrows receives the
 * number of rows allocated, which bounds the copy.
 */
void *
ppp_alloc_hash_copy(MemoryContext cxt, Size rowsize, int *maxrows,
					LWLockMode mode)
{
	for (;;)
	{
		long		n;
		void	   *buf;

		LWLockAcquire(ppp_shared->lock, LW_SHARED);
		n = hash_get_num_entries(ppp_role_hash);
		LWLockRelease(ppp_shared->lock);

		*maxrows = (int) n + PPP_HASH_COPY_MARGIN;
		buf = MemoryContextAlloc(cxt, rowsize * (Size) *maxrows);

		LWLockAcquire(ppp_shared->lock, mode);
		if (hash_get_num_entries(ppp_role_hash) <= *maxrows)
			return buf;
		LWLockRelease(ppp_shared->lock);
		pfree(buf);
	}
}

/* local copy of a hash entry, built under the lock */
typedef struct pppAttemptRow
{
	Oid			roleid;			/* key of the entry, InvalidOid: pseudo-entry */
	char		rolename[NAMEDATALEN];
	int32		failed_count;
	TimestampTz first_failure_at;
	TimestampTz last_failure_at;
	TimestampTz locked_until;
} pppAttemptRow;

/*
 * failed_attempts() RETURNS TABLE(role_name text, failed_count int,
 *	 first_failure_at timestamptz, last_failure_at timestamptz,
 *	 locked_until timestamptz, role_oid oid)
 *
 * Only entries with failures or an active lock are returned.  Timestamps at
 * 0 are returned as NULL; a manual lock (DT_NOEND) as 'infinity'.
 *
 * role_oid is the key of the entry (NULL for a pseudo-entry) and role_name
 * the current name of that role, looked up by OID outside the LWLock; once
 * the OID no longer exists (dropped role whose audit is pending), the last
 * name stored in the entry.
 *
 * Pseudo-entries (user names that matched no role when they were tried)
 * are returned by name to superusers only.  Such a name is whatever a client
 * typed in the user field, a password typed in the wrong field included;
 * the server log (readable by superusers) already holds it, the viewer and
 * admin roles must not read it.  For them, every pseudo-entry is folded
 * into a single row whose role_name and role_oid are NULL (it can match no
 * role, unlike a placeholder name): sum of the counters, earliest first
 * failure, latest last failure and latest lock.  This is decided on the key
 * alone: a role created since under such a name has an entry of its own,
 * keyed by its OID, and the pseudo-entry is not its state.  The entry of a
 * dropped role (OID no longer in pg_authid, role_dropped or not yet) is
 * folded into the same row: its last name is not shown to them either.
 */
Datum
ppp_failed_attempts(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	pppAttemptRow *rows;
	int			nrows = 0;
	int			maxrows;
	HASH_SEQ_STATUS seq;
	pppRoleEntry *entry;
	TimestampTz now;
	int			i;
	bool		show_missing = superuser();
	bool		have_agg = false;
	pppAttemptRow agg;

	ppp_check_shmem();
	ppp_begin_materialize(fcinfo, &tupdesc, &tupstore, 6);
	memset(&agg, 0, sizeof(agg));

	/* copy the interesting entries under a shared lock, no palloc inside */
	now = GetCurrentTimestamp();
	rows = (pppAttemptRow *) ppp_alloc_hash_copy(CurrentMemoryContext,
												 sizeof(pppAttemptRow),
												 &maxrows, LW_SHARED);
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
		rows[nrows].roleid = entry->key.roleid;
		strlcpy(rows[nrows].rolename, entry->rolename, NAMEDATALEN);
		rows[nrows].failed_count = entry->failed_count;
		rows[nrows].first_failure_at = entry->first_failure_at;
		rows[nrows].last_failure_at = entry->last_failure_at;
		rows[nrows].locked_until = locked ? entry->locked_until : 0;
		nrows++;
	}
	LWLockRelease(ppp_shared->lock);

	/* current name of each role, outside the lock */
	for (i = 0; i < nrows; i++)
	{
		HeapTuple	tup;

		if (!OidIsValid(rows[i].roleid))
			continue;
		tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(rows[i].roleid));
		if (HeapTupleIsValid(tup))
		{
			strlcpy(rows[i].rolename,
					NameStr(((Form_pg_authid) GETSTRUCT(tup))->rolname),
					NAMEDATALEN);
			ReleaseSysCache(tup);
		}
		else if (!show_missing)
			rows[i].roleid = InvalidOid;	/* dropped role: folded below */
	}

	/* fold the pseudo-entries and the entries of dropped roles (see above) */
	if (!show_missing)
	{
		int			kept = 0;

		for (i = 0; i < nrows; i++)
		{
			pppAttemptRow *r = &rows[i];

			if (OidIsValid(r->roleid))
			{
				if (kept != i)
					rows[kept] = *r;
				kept++;
				continue;
			}
			if (!have_agg)
			{
				agg = *r;
				have_agg = true;
				continue;
			}
			agg.failed_count += r->failed_count;
			if (r->first_failure_at != 0 &&
				(agg.first_failure_at == 0 || r->first_failure_at < agg.first_failure_at))
				agg.first_failure_at = r->first_failure_at;
			if (r->last_failure_at > agg.last_failure_at)
				agg.last_failure_at = r->last_failure_at;
			if (r->locked_until > agg.locked_until)
				agg.locked_until = r->locked_until;
		}
		nrows = kept;
		if (have_agg)
			rows[nrows++] = agg;	/* room: at least one row was dropped */
	}

	for (i = 0; i < nrows; i++)
	{
		Datum		values[6];
		bool		nulls[6];

		memset(nulls, 0, sizeof(nulls));
		if (!OidIsValid(rows[i].roleid) && !show_missing)
			nulls[0] = true;
		else
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
		if (OidIsValid(rows[i].roleid))
			values[5] = ObjectIdGetDatum(rows[i].roleid);
		else
			nulls[5] = true;

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	pfree(rows);

	return (Datum) 0;
}

/*
 * shmem_reload() RETURNS void
 *
 * Ask the worker to reload the lockout parameters of the profiles and the
 * persisted locks of role_state into shared memory.  The request is made
 * when the calling transaction commits (ppp_xact_callback, after the
 * commit is visible): reload_requested is set and SIGHUP is sent to the
 * worker (whose PID is published in ppp_shared->worker_pid), which treats
 * it as "reload the configuration file and run a cycle now".  Signalling
 * before the COMMIT would let the worker read the tables before the
 * caller's changes are visible and consume the request for nothing.  Not
 * signalled when called from the worker itself (run_maintenance() calls
 * shmem_reload()): the worker consumes reload_requested at its next step.
 * A ROLLBACK drops the request, and so does a ROLLBACK TO SAVEPOINT that
 * undoes the call (ppp_reload_subxid).
 */
Datum
ppp_shmem_reload(PG_FUNCTION_ARGS)
{
	ppp_require_superuser("shmem_reload");
	ppp_check_shmem();
	ppp_register_xact_callbacks();
	if (ppp_reload_subxid == InvalidSubTransactionId)
		ppp_reload_subxid = GetCurrentSubTransactionId();

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
 * Key of a role given by name (shmem_unlock_role(), shmem_reset_failures()):
 * its OID when a role bears that name, the pseudo-key of the name otherwise
 * (so that a pseudo-lock of an invented name can be lifted).
 */
static void
ppp_name_key(const char *rolename, pppRoleKey *key)
{
	ppp_make_key(key, get_role_oid(rolename, true), rolename);
}

/*
 * Name of a role given by OID, for messages: ERROR 42704 when the OID does
 * not exist unless missing_ok (the OID itself is then used).
 */
static void
ppp_oid_dispname(Oid roleid, char *buf, bool missing_ok)
{
	HeapTuple	tup;

	tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(roleid));
	if (!HeapTupleIsValid(tup))
	{
		if (!missing_ok)
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_OBJECT),
					 errmsg("role with OID %u does not exist", roleid)));
		snprintf(buf, NAMEDATALEN, "%u", roleid);
		return;
	}
	strlcpy(buf, NameStr(((Form_pg_authid) GETSTRUCT(tup))->rolname),
			NAMEDATALEN);
	ReleaseSysCache(tup);
}

/*
 * Role OID argument of _shmem_unlock(), _shmem_reset() and
 * _shmem_is_locked() (STRICT): InvalidOid would build a pseudo-key without
 * name (ppp_make_key), hence the explicit refusal.
 */
static Oid
ppp_arg_roleid(FunctionCallInfo fcinfo)
{
	Oid			roleid = PG_GETARG_OID(0);

	if (!OidIsValid(roleid))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid role OID")));
	return roleid;
}

/* end of a lock: argument argno, NULL or 'infinity' = until manual unlock */
static TimestampTz
ppp_arg_until(FunctionCallInfo fcinfo, int argno)
{
	TimestampTz until;

	if (PG_ARGISNULL(argno))
		return DT_NOEND;
	until = PG_GETARG_TIMESTAMPTZ(argno);
	if (TIMESTAMP_IS_NOEND(until))
		return DT_NOEND;
	if (TIMESTAMP_IS_NOBEGIN(until))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("lock end time must not be -infinity")));
	return until;
}

/*
 * shmem_lock_role(role text, until timestamptz) RETURNS void
 *
 * Direct use by a superuser (standby included); lock_role() calls
 * _shmem_lock() with the OID it has checked.  ERROR 42704 without a role of
 * that name.  until NULL (or 'infinity') = locked until manual unlock.  The
 * lock is queued for the OID of the role, captured now, and applied at
 * PRE_COMMIT: a rename later in the transaction keeps it on the role.  If
 * the shared memory has no room for it (every entry holds an active lock, a
 * lock not yet audited or profile parameters of an existing role), the
 * COMMIT fails with an ERROR (ppp_apply_lock_ops).  On a primary, a lock
 * set this way without a role_state row (direct call, not through
 * lock_role()) is lifted by the next worker reload.
 */
Datum
ppp_shmem_lock_role(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	TimestampTz until;
	pppRoleKey	key;

	ppp_require_superuser("shmem_lock_role");
	ppp_check_shmem();

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("role name must not be NULL")));
	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);
	ppp_make_key(&key, get_role_oid(rolename, false), rolename);
	until = ppp_arg_until(fcinfo, 1);

	ppp_defer_op(PPP_OP_LOCK, &key, rolename, until, false);

	PG_RETURN_VOID();
}

/*
 * _shmem_lock(role oid, until timestamptz) RETURNS void
 *
 * Internal (lock_role()): shmem_lock_role() for the OID the caller has
 * checked, so that a rename between that check and this call cannot lock
 * another role in shared memory than in role_state.  ERROR 42704 if the OID
 * does not exist.
 */
Datum
ppp_shmem_lock_oid(PG_FUNCTION_ARGS)
{
	char		dispname[NAMEDATALEN];
	Oid			roleid;
	TimestampTz until;
	pppRoleKey	key;

	ppp_require_superuser("_shmem_lock");
	ppp_check_shmem();

	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("role OID must not be NULL")));
	roleid = PG_GETARG_OID(0);
	ppp_oid_dispname(roleid, dispname, false);
	ppp_make_key(&key, roleid, NULL);
	until = ppp_arg_until(fcinfo, 1);

	ppp_defer_op(PPP_OP_LOCK, &key, dispname, until, false);

	PG_RETURN_VOID();
}

/*
 * Queue the unlock of an entry (see ppp_shmem_unlock_role).  Returns false,
 * and queues nothing, when expired_only is set and the entry holds an
 * active lock right now.
 */
static bool
ppp_queue_unlock(const pppRoleKey *key, const char *dispname,
				 bool expired_only)
{
	if (expired_only)
	{
		pppRoleEntry *entry;
		bool		locked = false;

		LWLockAcquire(ppp_shared->lock, LW_SHARED);
		entry = (pppRoleEntry *) hash_search(ppp_role_hash, key, HASH_FIND, NULL);
		if (entry != NULL)
			locked = ppp_is_locked(entry, GetCurrentTimestamp());
		LWLockRelease(ppp_shared->lock);
		if (locked)
			return false;
	}

	ppp_defer_op(PPP_OP_UNLOCK, key, dispname, 0, expired_only);
	return true;
}

/*
 * shmem_unlock_role(role text, expired_only bool DEFAULT false) RETURNS bool
 * (STRICT)
 *
 * Direct use by a superuser (standby included); unlock_role() and
 * run_maintenance() call _shmem_unlock() with an OID.  The entry is that of
 * the OID of the role that bears the name, or, without such a role, the
 * pseudo-entry of the name.
 *
 * Removes the lock at COMMIT, except a lock that the caller cannot have
 * seen (see ppp_unlock_allowed); with expired_only, only a lock that has
 * expired by then.  The failure counter is left alone (see
 * shmem_reset_failures).
 *
 * Returns false, and queues nothing, when expired_only is set and the
 * shared memory holds an active lock of the role right now (a newer
 * automatic lock that role_state does not know yet): the unlock would be
 * refused at COMMIT, and step f of run_maintenance() must then neither
 * audit nor report it.  True otherwise (unlock queued).  A lock set
 * between this call and the COMMIT is still kept at COMMIT (LOG), the
 * answer then being optimistic.
 */
Datum
ppp_shmem_unlock_role(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	pppRoleKey	key;

	ppp_require_superuser("shmem_unlock_role");
	ppp_check_shmem();

	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);
	ppp_name_key(rolename, &key);

	PG_RETURN_BOOL(ppp_queue_unlock(&key, rolename, PG_GETARG_BOOL(1)));
}

/* _shmem_unlock(role oid, expired_only bool) RETURNS bool (STRICT, internal) */
Datum
ppp_shmem_unlock_oid(PG_FUNCTION_ARGS)
{
	char		dispname[NAMEDATALEN];
	Oid			roleid;
	pppRoleKey	key;

	ppp_require_superuser("_shmem_unlock");
	ppp_check_shmem();
	roleid = ppp_arg_roleid(fcinfo);

	ppp_oid_dispname(roleid, dispname, true);
	ppp_make_key(&key, roleid, NULL);

	PG_RETURN_BOOL(ppp_queue_unlock(&key, dispname, PG_GETARG_BOOL(1)));
}

/*
 * _shmem_is_locked(role oid) RETURNS bool (STRICT)
 *
 * True if the shared memory holds an active lock of the role right now
 * (HASH_FIND under a shared lock).  Used by unlock_role() to tell whether
 * there was anything to unlock, without copying the whole hash as
 * failed_attempts() does; shmem_unlock_role() cannot answer that (without
 * expired_only it queues the unlock and returns true).
 */
Datum
ppp_shmem_is_locked(PG_FUNCTION_ARGS)
{
	pppRoleKey	key;
	pppRoleEntry *entry;
	bool		locked = false;

	ppp_require_superuser("_shmem_is_locked");
	ppp_check_shmem();

	ppp_make_key(&key, ppp_arg_roleid(fcinfo), NULL);
	LWLockAcquire(ppp_shared->lock, LW_SHARED);
	entry = (pppRoleEntry *) hash_search(ppp_role_hash, &key, HASH_FIND, NULL);
	if (entry != NULL)
		locked = ppp_is_locked(entry, GetCurrentTimestamp());
	LWLockRelease(ppp_shared->lock);

	PG_RETURN_BOOL(locked);
}

/*
 * shmem_reset_failures(role text) RETURNS void (STRICT)
 *
 * Resets the failure counter at COMMIT (entry chosen as by
 * shmem_unlock_role()).  Failures not yet written to the audit log
 * (pending_failures) are kept: they did happen.
 */
Datum
ppp_shmem_reset_failures(PG_FUNCTION_ARGS)
{
	char		rolename[NAMEDATALEN];
	pppRoleKey	key;

	ppp_require_superuser("shmem_reset_failures");
	ppp_check_shmem();

	ppp_text_to_rolename(PG_GETARG_TEXT_PP(0), rolename);
	ppp_name_key(rolename, &key);

	ppp_defer_op(PPP_OP_RESET, &key, rolename, 0, false);

	PG_RETURN_VOID();
}

/* _shmem_reset(role oid) RETURNS void (STRICT, internal: unlock_role()) */
Datum
ppp_shmem_reset_oid(PG_FUNCTION_ARGS)
{
	char		dispname[NAMEDATALEN];
	Oid			roleid;
	pppRoleKey	key;

	ppp_require_superuser("_shmem_reset");
	ppp_check_shmem();
	roleid = ppp_arg_roleid(fcinfo);

	ppp_oid_dispname(roleid, dispname, true);
	ppp_make_key(&key, roleid, NULL);

	ppp_defer_op(PPP_OP_RESET, &key, dispname, 0, false);

	PG_RETURN_VOID();
}

/*
 * _system_identifier() RETURNS bigint
 *
 * pg_control's system identifier (GetSystemIdentifier(), PG 14 to 18):
 * default of the cluster_id columns of role_state and role_profile, which
 * tell the rows written in this cluster (or a physical replica of it) from
 * rows restored from another one (SPEC 6.3, "Rechargement").  The uint64 is
 * returned as its bit pattern, like pg_control_system().
 */
Datum
ppp_system_identifier(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT64((int64) GetSystemIdentifier());
}
