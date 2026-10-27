/* worker.c — squelette : background worker. À compléter (agent lockout/worker). */
#include "postgres.h"
#include "fmgr.h"
#include "pg_pass_policy.h"
#include "compat.h"

void
ppp_worker_register(void)
{
}

PGDLLEXPORT void
ppp_worker_main(Datum main_arg)
{
}
