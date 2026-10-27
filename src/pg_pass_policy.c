/* pg_pass_policy.c — squelette : _PG_init, GUC, shmem. À compléter (agent core). */
#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "utils/guc.h"
#include "pg_pass_policy.h"
#include "compat.h"

PG_MODULE_MAGIC;

bool  ppp_enabled = true;
char *ppp_database = NULL;
int   ppp_worker_interval = 60;
int   ppp_max_tracked_roles = 1024;
bool  ppp_manage_valid_until = true;
bool  ppp_log_events = true;
char *ppp_notify_channel = NULL;
char *ppp_exempt_roles = NULL;
bool  ppp_superuser_bypass = false;
bool  ppp_require_scram = true;
bool  ppp_enforce_database = true;

pppSharedState *ppp_shared = NULL;
HTAB *ppp_role_hash = NULL;

void _PG_init(void);

Size
ppp_shmem_size(void)
{
	return 0;
}

bool
ppp_role_is_exempt(const char *rolename)
{
	return false;
}

void
ppp_secure_zero(void *p, size_t len)
{
	volatile unsigned char *vp = (volatile unsigned char *) p;
	while (len--)
		*vp++ = 0;
}

void
_PG_init(void)
{
}
