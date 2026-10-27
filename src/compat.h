/*
 * compat.h — différences entre les versions de PostgreSQL supportées (14 → 18).
 * Seul fichier autorisé à tester PG_VERSION_NUM.
 */
#ifndef PPP_COMPAT_H
#define PPP_COMPAT_H

#include "postgres.h"

#if PG_VERSION_NUM < 140000
#error "pg_pass_policy requires PostgreSQL 14 or later"
#endif

/* shmem_request_hook n'existe qu'à partir de PG 15 */
#if PG_VERSION_NUM >= 150000
#define PPP_HAVE_SHMEM_REQUEST_HOOK 1
#endif

/* MarkGUCPrefixReserved remplace EmitWarningsOnPlaceholders en PG 15 */
#if PG_VERSION_NUM >= 150000
#define PPP_RESERVE_GUC_PREFIX(prefix) MarkGUCPrefixReserved(prefix)
#else
#define PPP_RESERVE_GUC_PREFIX(prefix) EmitWarningsOnPlaceholders(prefix)
#endif

#endif							/* PPP_COMPAT_H */
