/*
 * compat.h — differences between the supported PostgreSQL versions (14 -> 18).
 *
 * This is the ONLY file allowed to test PG_VERSION_NUM.  Every #if below is
 * documented with the reason and the version that introduced the change.
 * Signatures were checked against the installed PG 16.4 headers; for 14, 15,
 * 17 and 18 they come from the PostgreSQL source history (see comments).
 */
#ifndef PPP_COMPAT_H
#define PPP_COMPAT_H

#include "postgres.h"

#if PG_VERSION_NUM < 140000
#error "pg_pass_policy requires PostgreSQL 14 or later"
#endif

/*
 * Module magic.  PG 18 introduced PG_MODULE_MAGIC_EXT, which records a name
 * and a version visible in pg_get_loaded_modules().  Older versions only
 * know PG_MODULE_MAGIC (still accepted by PG 18).
 */
#if PG_VERSION_NUM >= 180000
#define PPP_MODULE_MAGIC PG_MODULE_MAGIC_EXT(.name = "pg_pass_policy", .version = "1.0")
#else
#define PPP_MODULE_MAGIC PG_MODULE_MAGIC
#endif

/*
 * shmem_request_hook was added in PG 15.  Before that,
 * RequestAddinShmemSpace() and RequestNamedLWLockTranche() are called
 * directly from _PG_init() while process_shared_preload_libraries_in_progress.
 */
#if PG_VERSION_NUM >= 150000
#define PPP_HAVE_SHMEM_REQUEST_HOOK 1
#endif

/*
 * MarkGUCPrefixReserved() replaced EmitWarningsOnPlaceholders() in PG 15
 * (the latter is kept as a deprecated macro there, but MarkGUCPrefixReserved
 * also removes existing bogus placeholders).
 */
#if PG_VERSION_NUM >= 150000
#define PPP_RESERVE_GUC_PREFIX(prefix) MarkGUCPrefixReserved(prefix)
#else
#define PPP_RESERVE_GUC_PREFIX(prefix) EmitWarningsOnPlaceholders(prefix)
#endif

/*
 * pg_md5_encrypt() (common/md5.h):
 *   PG 14     : bool pg_md5_encrypt(const char *passwd, const char *salt,
 *                                   size_t salt_len, char *buf);
 *   PG 15-18  : same plus a trailing "const char **errstr" (added
 *               with cryptohash error reporting in PG 15).
 * The salt is passed as "const void *" by callers of this macro so that a
 * possible switch of the salt type to an unsigned byte pointer does not
 * produce a warning (void * converts implicitly).
 */
#if PG_VERSION_NUM >= 150000
#define PPP_MD5_ENCRYPT(passwd, salt, salt_len, buf, errstr) \
	pg_md5_encrypt((passwd), (salt), (salt_len), (buf), (errstr))
#else
#define PPP_MD5_ENCRYPT(passwd, salt, salt_len, buf, errstr) \
	((void) (errstr), pg_md5_encrypt((passwd), (salt), (salt_len), (buf)))
#endif

/*
 * The following APIs are used unchanged on PG 14 -> 18 and need no shim
 * (listed here so a reviewer knows they were checked):
 *   - check_password_hook_type (commands/user.h): (const char *username,
 *     const char *shadow_pass, PasswordType password_type,
 *     Datum validuntil_time, bool validuntil_null);
 *   - encrypt_password(PasswordType, const char *role, const char *password)
 *     and get_password_type(const char *) in libpq/crypt.h;
 *   - scram_verify_plain_password(const char *username, const char *password,
 *     const char *secret) in libpq/scram.h;
 *   - pg_strong_random(void *buf, size_t len) in port.h;
 *   - SplitIdentifierString() in utils/varlena.h;
 *   - str_tolower(const char *, size_t, Oid) in utils/formatting.h;
 *   - hash_get_num_entries() returns "long" up to PG 17 and "int64" in PG 18:
 *     callers cast the result explicitly.
 * PG 18 only emits a deprecation WARNING when an MD5 password is set; the
 * extension computes SCRAM verifiers only, so nothing changes for us.
 */

#endif							/* PPP_COMPAT_H */
