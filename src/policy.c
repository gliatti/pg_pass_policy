/*-------------------------------------------------------------------------
 *
 * policy.c
 *		check_password_hook (complexity, dictionary, minimum age, history,
 *		recording of the new verifier) and the SQL functions
 *		pass_policy.check_password() / generate_password().
 *
 * See docs/SPEC.md section 6.2.
 *
 * Security rules (SPEC 8): the clear-text password is never passed to SQL,
 * never written in a message, a log line or the audit trail, and every
 * buffer that held it is wiped with ppp_secure_zero() before being freed.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <string.h>

#include "access/xact.h"
#include "catalog/namespace.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"
#include "commands/user.h"
#include "common/md5.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "libpq/crypt.h"
#include "libpq/scram.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/formatting.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/syscache.h"

#include "pg_pass_policy.h"
#include "compat.h"

PG_FUNCTION_INFO_V1(ppp_check_password);
PG_FUNCTION_INFO_V1(ppp_generate_password);
PG_FUNCTION_INFO_V1(ppp_in_password_hook);

static check_password_hook_type prev_check_password_hook = NULL;

/* WARNING "extension not installed here" emitted once per session */
static bool ppp_missing_schema_warned = false;

/*
 * True while this backend runs the password hook: lets the SQL side
 * (record_password_change(), audit()) accept calls coming from the hook.
 */
static bool ppp_in_hook = false;

/* Generated passwords: lengths accepted by generate_password() */
#define PPP_GEN_MIN_LENGTH	8
#define PPP_GEN_MAX_LENGTH	512
#define PPP_GEN_MAX_TRIES	100

/* Alphabet without ambiguous characters 0 O 1 l I | */
static const char ppp_alpha_lower[] = "abcdefghijkmnopqrstuvwxyz";
static const char ppp_alpha_upper[] = "ABCDEFGHJKLMNPQRSTUVWXYZ";
static const char ppp_alpha_digit[] = "23456789";
static const char ppp_alpha_special[] = "!#%()*+,-./:;=?@[]^_{}~";

/*
 * Effective profile (subset of pass_policy.profile used by the checks).
 */
typedef struct pppProfile
{
	char	   *name;
	int32		min_length;
	int32		max_length;
	int32		min_lower;
	int32		min_upper;
	int32		min_digit;
	int32		min_special;
	int32		min_classes;
	bool		reject_username;
	bool		reject_dictionary;
	bool		reject_prehashed;
	int32		max_repeat;
	int32		history_count;
	int32		history_days;
	bool		min_age_null;
	Datum		min_age;		/* interval, palloc'd in caller context */
	char	   *min_age_text;	/* for messages */
} pppProfile;

/* State saved while running SPI as the bootstrap superuser */
typedef struct pppSpiState
{
	Oid			save_userid;
	int			save_sec_context;
	int			save_nestlevel;
} pppSpiState;

static void ppp_check_password_hook(const char *username,
									const char *shadow_pass,
									PasswordType password_type,
									Datum validuntil_time,
									bool validuntil_null);


/* ------------------------------------------------------------------------
 * SPI helpers
 * ------------------------------------------------------------------------
 */

/*
 * Open an SPI connection running as the bootstrap superuser with a safe
 * search_path.  The pg_pass_policy tables are not readable by PUBLIC, while
 * the hook runs with the privileges of whoever executes ALTER ROLE (possibly
 * an unprivileged role changing its own password).  All queries issued
 * through this are fixed, schema-qualified statements of this file.
 */
static void
ppp_spi_begin(pppSpiState *st)
{
	GetUserIdAndSecContext(&st->save_userid, &st->save_sec_context);
	SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID,
						   st->save_sec_context | SECURITY_LOCAL_USERID_CHANGE |
						   SECURITY_RESTRICTED_OPERATION);
	st->save_nestlevel = NewGUCNestLevel();
	(void) set_config_option("search_path", "pg_catalog, pg_temp",
							 PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);

	/*
	 * Messages raised on the SQL side (e.g. RAISE LOG in audit()) must not
	 * carry the STATEMENT, which may be ALTER ROLE ... PASSWORD 'clear text'.
	 */
	(void) set_config_option("log_min_error_statement", "panic",
							 PGC_SUSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "pg_pass_policy: SPI_connect failed");
}

static void
ppp_spi_end(pppSpiState *st)
{
	SPI_finish();
	AtEOXact_GUC(true, st->save_nestlevel);
	SetUserIdAndSecContext(st->save_userid, st->save_sec_context);
}

/* Is the pg_pass_policy schema present in the current database? */
static bool
ppp_schema_exists(void)
{
	return OidIsValid(get_namespace_oid(PPP_SCHEMA, true));
}

static int
ppp_col(const char *colname)
{
	int			fno = SPI_fnumber(SPI_tuptable->tupdesc, colname);

	if (fno <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("pg_pass_policy: column \"%s\" is missing from the profile",
						colname)));
	return fno;
}

static int32
ppp_get_int(HeapTuple tup, const char *colname, int32 defval)
{
	bool		isnull;
	Datum		d;

	d = SPI_getbinval(tup, SPI_tuptable->tupdesc, ppp_col(colname), &isnull);
	return isnull ? defval : DatumGetInt32(d);
}

static bool
ppp_get_bool(HeapTuple tup, const char *colname, bool defval)
{
	bool		isnull;
	Datum		d;

	d = SPI_getbinval(tup, SPI_tuptable->tupdesc, ppp_col(colname), &isnull);
	return isnull ? defval : DatumGetBool(d);
}

/*
 * Fill *p from the first row of SPI_tuptable.  Strings and the interval are
 * allocated in "cxt" so that they survive SPI_finish().
 */
static void
ppp_profile_from_spi(pppProfile *p, MemoryContext cxt)
{
	HeapTuple	tup = SPI_tuptable->vals[0];
	MemoryContext old;
	bool		isnull;
	Datum		d;
	char	   *s;

	p->min_length = ppp_get_int(tup, "min_length", 12);
	p->max_length = ppp_get_int(tup, "max_length", 128);
	p->min_lower = ppp_get_int(tup, "min_lower", 1);
	p->min_upper = ppp_get_int(tup, "min_upper", 1);
	p->min_digit = ppp_get_int(tup, "min_digit", 1);
	p->min_special = ppp_get_int(tup, "min_special", 1);
	p->min_classes = ppp_get_int(tup, "min_classes", 3);
	p->reject_username = ppp_get_bool(tup, "reject_username", true);
	p->reject_dictionary = ppp_get_bool(tup, "reject_dictionary", true);
	p->reject_prehashed = ppp_get_bool(tup, "reject_prehashed", true);
	p->max_repeat = ppp_get_int(tup, "max_repeat", 3);
	p->history_count = ppp_get_int(tup, "history_count", 5);
	p->history_days = ppp_get_int(tup, "history_days", 365);

	s = SPI_getvalue(tup, SPI_tuptable->tupdesc, ppp_col("name"));
	d = SPI_getbinval(tup, SPI_tuptable->tupdesc, ppp_col("min_age"), &isnull);

	old = MemoryContextSwitchTo(cxt);
	p->name = pstrdup(s ? s : "?");
	p->min_age_null = isnull;
	if (!isnull)
	{
		p->min_age = datumCopy(d, false, sizeof(Interval));
		s = SPI_getvalue(tup, SPI_tuptable->tupdesc, ppp_col("min_age"));
		p->min_age_text = pstrdup(s ? s : "");
	}
	else
	{
		p->min_age = (Datum) 0;
		p->min_age_text = NULL;
	}
	MemoryContextSwitchTo(old);
}

/*
 * Load the effective profile of a role through
 * pass_policy.effective_profile(name).  The role may not exist yet
 * (CREATE ROLE): effective_profile() then returns the default profile.
 */
static void
ppp_load_effective_profile(const char *rolename, pppProfile *p)
{
	MemoryContext cxt = CurrentMemoryContext;
	pppSpiState st;
	Oid			argtypes[1] = {NAMEOID};
	Datum		values[1];
	int			ret;

	values[0] = DirectFunctionCall1(namein, CStringGetDatum(rolename));

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT * FROM " PPP_SCHEMA ".effective_profile($1)",
								1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: effective_profile() failed: %s",
			 SPI_result_code_string(ret));
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pg_pass_policy: no effective profile for role \"%s\"",
						rolename)));
	ppp_profile_from_spi(p, cxt);
	ppp_spi_end(&st);
}

/* Load a profile by name (generate_password) */
static void
ppp_load_named_profile(const char *profname, pppProfile *p)
{
	MemoryContext cxt = CurrentMemoryContext;
	pppSpiState st;
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;

	values[0] = CStringGetTextDatum(profname);

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT * FROM " PPP_SCHEMA ".profile WHERE name = $1",
								1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: profile lookup failed: %s",
			 SPI_result_code_string(ret));
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pg_pass_policy: profile \"%s\" does not exist", profname)));
	ppp_profile_from_spi(p, cxt);
	ppp_spi_end(&st);
}


/* ------------------------------------------------------------------------
 * Complexity checks (SPEC 6.2 step 4)
 * ------------------------------------------------------------------------
 */

/* Lower-case a secret; the caller must ppp_secure_zero() the result. */
static char *
ppp_lower(const char *s)
{
	return str_tolower(s, strlen(s), DEFAULT_COLLATION_OID);
}

/* Reverse a string character by character (multibyte aware) */
static char *
ppp_reverse(const char *s)
{
	size_t		len = strlen(s);
	char	   *r = palloc(len + 1);
	const char *p = s;
	char	   *q = r + len;

	r[len] = '\0';
	while (*p)
	{
		int			l = pg_mblen(p);

		q -= l;
		memcpy(q, p, l);
		p += l;
	}
	return r;
}

/*
 * Is the (already lower-cased) password one of the words of
 * pass_policy.dictionary?  Only the length of the password is sent to
 * SQL; the comparison itself is done here.
 */
static bool
ppp_in_dictionary(const char *lower_pw)
{
	pppSpiState st;
	Oid			argtypes[1] = {INT4OID};
	Datum		values[1];
	int			ret;
	bool		found = false;
	uint64		i;

	values[0] = Int32GetDatum(pg_mbstrlen(lower_pw));

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT pg_catalog.lower(word) FROM " PPP_SCHEMA ".dictionary "
								"WHERE pg_catalog.length(word) = $1",
								1, argtypes, values, NULL, true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: dictionary lookup failed: %s",
			 SPI_result_code_string(ret));
	for (i = 0; i < SPI_processed && !found; i++)
	{
		bool		isnull;
		Datum		d;
		text	   *t;

		d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1,
						  &isnull);
		if (isnull)
			continue;
		t = DatumGetTextPP(d);
		if (VARSIZE_ANY_EXHDR(t) == strlen(lower_pw) &&
			memcmp(VARDATA_ANY(t), lower_pw, VARSIZE_ANY_EXHDR(t)) == 0)
			found = true;
	}
	ppp_spi_end(&st);

	return found;
}

/*
 * Validate the clear-text password against the complexity rules of the
 * profile, in the order of SPEC 6.2 step 4.  Returns true if the password is
 * acceptable; otherwise sets *code to a static "PPP-0xx" string.
 *
 * The dictionary lookup opens its own SPI connection.
 */
static bool
ppp_validate(const char *username, const char *password, const pppProfile *p,
			 const char **code)
{
	const char *c;
	int			nchars = 0;
	int			nlower = 0,
				nupper = 0,
				ndigit = 0,
				nspecial = 0;
	int			nclasses;
	bool		nonprintable = false;
	int			run = 0;
	int			maxrun = 0;
	const char *prev = NULL;
	int			prevlen = 0;
	size_t		pwlen = strlen(password);

	*code = NULL;

	for (c = password; *c; c += prevlen)
	{
		int			l = pg_mblen(c);
		unsigned char ch = (unsigned char) *c;

		nchars++;
		if (l == 1)
		{
			if (ch >= 'a' && ch <= 'z')
				nlower++;
			else if (ch >= 'A' && ch <= 'Z')
				nupper++;
			else if (ch >= '0' && ch <= '9')
				ndigit++;
			else if (ch < 0x20 || ch == 0x7f)
				nonprintable = true;
			else
				nspecial++;
		}
		else
			nspecial++;			/* any non-ASCII character is "special" */

		/* consecutive identical characters */
		if (prev != NULL && prevlen == l && memcmp(prev, c, l) == 0)
			run++;
		else
			run = 1;
		if (run > maxrun)
			maxrun = run;

		prev = c;
		prevlen = l;
	}

	if (pwlen > 0 && (password[0] == ' ' || password[pwlen - 1] == ' '))
		nonprintable = true;

	nclasses = (nlower > 0) + (nupper > 0) + (ndigit > 0) + (nspecial > 0);

	if (nchars < p->min_length)
		*code = "PPP-010";
	else if (p->max_length > 0 && nchars > p->max_length)
		*code = "PPP-011";
	else if (nclasses < p->min_classes)
		*code = "PPP-012";
	else if (nlower < p->min_lower)
		*code = "PPP-013";
	else if (nupper < p->min_upper)
		*code = "PPP-014";
	else if (ndigit < p->min_digit)
		*code = "PPP-015";
	else if (nspecial < p->min_special)
		*code = "PPP-016";

	if (*code)
		return false;

	if (p->reject_username || p->reject_dictionary)
	{
		char	   *lower_pw = ppp_lower(password);
		bool		bad = false;

		/*
		 * Role names of fewer than 3 characters are ignored: they would
		 * reject nearly every password.
		 */
		if (p->reject_username && pg_mbstrlen(username) >= 3)
		{
			char	   *lower_user = ppp_lower(username);
			char	   *rev_user = ppp_reverse(lower_user);

			if (strstr(lower_pw, lower_user) != NULL ||
				strstr(lower_pw, rev_user) != NULL)
			{
				*code = "PPP-017";
				bad = true;
			}
			pfree(lower_user);
			pfree(rev_user);
		}

		if (!bad && p->reject_dictionary && ppp_in_dictionary(lower_pw))
		{
			*code = "PPP-018";
			bad = true;
		}

		ppp_secure_zero(lower_pw, strlen(lower_pw));
		pfree(lower_pw);
		if (bad)
			return false;
	}

	if (p->max_repeat > 0 && maxrun > p->max_repeat)
		*code = "PPP-019";
	else if (nonprintable)
		*code = "PPP-020";

	return *code == NULL;
}

/*
 * Human readable reason for a code.  *msg is the short errmsg() text (after
 * the code), *detail the errdetail() text.  Never contains the password.
 */
static void
ppp_describe(const char *code, const pppProfile *p, char **msg, char **detail,
			 char **hint)
{
	*msg = NULL;
	*detail = NULL;
	*hint = NULL;

	if (strcmp(code, "PPP-001") == 0)
	{
		*msg = pstrdup("pre-hashed passwords are not allowed");
		*detail = pstrdup("The password policy cannot be verified on an MD5 or SCRAM verifier.");
		*hint = pstrdup("Provide the password in clear text (preferably over an encrypted connection) or use rotate_password() of the extension.");
	}
	else if (strcmp(code, "PPP-002") == 0)
	{
		*msg = pstrdup("MD5 passwords are not allowed");
		*detail = pstrdup("pg_pass_policy.require_scram is enabled.");
		*hint = pstrdup("Set password_encryption to 'scram-sha-256'.");
	}
	else if (strcmp(code, "PPP-003") == 0)
	{
		*msg = psprintf("password changes must be made while connected to database \"%s\"",
						ppp_database);
		*detail = pstrdup("The pg_pass_policy extension (schema " PPP_SCHEMA ") is not installed in the current database.");
		*hint = pstrdup("Connect to the database designated by pg_pass_policy.database, or disable pg_pass_policy.enforce_database.");
	}
	else if (strcmp(code, "PPP-010") == 0)
	{
		*msg = pstrdup("password is too short");
		*detail = psprintf("The password must contain at least %d characters.",
						   p->min_length);
	}
	else if (strcmp(code, "PPP-011") == 0)
	{
		*msg = pstrdup("password is too long");
		*detail = psprintf("The password must contain at most %d characters.",
						   p->max_length);
	}
	else if (strcmp(code, "PPP-012") == 0)
	{
		*msg = pstrdup("password does not contain enough character classes");
		*detail = psprintf("The password must contain at least %d of the 4 character classes (lowercase, uppercase, digit, special).",
						   p->min_classes);
	}
	else if (strcmp(code, "PPP-013") == 0)
	{
		*msg = pstrdup("password does not contain enough lowercase letters");
		*detail = psprintf("The password must contain at least %d lowercase letter(s).",
						   p->min_lower);
	}
	else if (strcmp(code, "PPP-014") == 0)
	{
		*msg = pstrdup("password does not contain enough uppercase letters");
		*detail = psprintf("The password must contain at least %d uppercase letter(s).",
						   p->min_upper);
	}
	else if (strcmp(code, "PPP-015") == 0)
	{
		*msg = pstrdup("password does not contain enough digits");
		*detail = psprintf("The password must contain at least %d digit(s).",
						   p->min_digit);
	}
	else if (strcmp(code, "PPP-016") == 0)
	{
		*msg = pstrdup("password does not contain enough special characters");
		*detail = psprintf("The password must contain at least %d special character(s).",
						   p->min_special);
	}
	else if (strcmp(code, "PPP-017") == 0)
	{
		*msg = pstrdup("password contains the role name");
		*detail = pstrdup("The password must not contain the role name, in any case and even reversed.");
	}
	else if (strcmp(code, "PPP-018") == 0)
	{
		*msg = pstrdup("password is too common");
		*detail = pstrdup("The password appears in the dictionary of common passwords.");
	}
	else if (strcmp(code, "PPP-019") == 0)
	{
		*msg = pstrdup("password contains too many repeated characters");
		*detail = psprintf("The password must not contain more than %d identical consecutive characters.",
						   p->max_repeat);
	}
	else if (strcmp(code, "PPP-020") == 0)
	{
		*msg = pstrdup("password contains invalid characters");
		*detail = pstrdup("The password must not contain control characters, nor start or end with a space.");
	}
	else if (strcmp(code, "PPP-030") == 0)
	{
		*msg = pstrdup("password was changed too recently");
		*detail = psprintf("The minimum password age is %s.",
						   p->min_age_text ? p->min_age_text : "?");
	}
	else if (strcmp(code, "PPP-031") == 0)
	{
		*msg = pstrdup("password was used recently");
		*detail = psprintf("The password must differ from the current one and from the last %d passwords.",
						   p->history_count);
	}
	else
		*msg = pstrdup("password rejected by pg_pass_policy");

	if (*hint == NULL && strncmp(code, "PPP-01", 6) == 0)
		*hint = psprintf("Profile \"%s\" applies; generate_password() returns a compliant password.",
						 p->name);
}


/* ------------------------------------------------------------------------
 * Minimum age and history (SPEC 6.2 steps 5 and 6)
 * ------------------------------------------------------------------------
 */

/*
 * True if the role changed its password less than min_age ago.  Not
 * applicable when the password was force-expired (must_change).
 */
static bool
ppp_min_age_violated(const char *username, Oid roleid, const pppProfile *p)
{
	pppSpiState st;
	Oid			argtypes[3] = {OIDOID, INTERVALOID, TEXTOID};
	Datum		values[3];
	int			ret;
	bool		violated = false;

	if (!OidIsValid(roleid) || p->min_age_null)
		return false;

	values[0] = ObjectIdGetDatum(roleid);
	values[1] = p->min_age;
	values[2] = CStringGetTextDatum(username);

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT pg_catalog.bool_or((pg_catalog.now() - password_changed_at) < $2) "
								"FROM " PPP_SCHEMA ".role_state "
								"WHERE (role_oid = $1 OR role_name = $3) "
								"AND password_changed_at IS NOT NULL "
								"AND NOT coalesce(must_change, false)",
								3, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: role_state lookup failed: %s",
			 SPI_result_code_string(ret));
	if (SPI_processed > 0)
	{
		bool		isnull;
		Datum		d;

		d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1,
						  &isnull);
		violated = !isnull && DatumGetBool(d);
	}
	ppp_spi_end(&st);

	return violated;
}

/* Does the clear-text password match the stored verifier? */
static bool
ppp_matches_verifier(const char *username, const char *password,
					 const char *verifier)
{
	switch (get_password_type(verifier))
	{
		case PASSWORD_TYPE_SCRAM_SHA_256:
			return scram_verify_plain_password(username, password, verifier);
		case PASSWORD_TYPE_MD5:
			{
				char		buf[MD5_PASSWD_LEN + 1];
				const char *errstr = NULL;
				bool		match = false;

				if (PPP_MD5_ENCRYPT(password, (const void *) username,
									strlen(username), buf, &errstr))
					match = (strcmp(buf, verifier) == 0);
				ppp_secure_zero(buf, sizeof(buf));
				return match;
			}
		default:
			/* clear-text verifiers are not stored since PG 10 */
			return false;
	}
}

/*
 * True if the password matches the current verifier of the role or one of
 * the history_count most recent verifiers of pass_policy.password_history
 * (not older than history_days).
 */
static bool
ppp_password_reused(const char *username, Oid roleid, const char *password,
					const pppProfile *p)
{
	pppSpiState st;
	Oid			argtypes[4] = {OIDOID, INT4OID, INT4OID, TEXTOID};
	Datum		values[4];
	int			ret;
	bool		reused = false;
	uint64		i;
	HeapTuple	tup;

	if (p->history_count <= 0 || !OidIsValid(roleid))
		return false;

	/* current password (also covers roles that predate the extension) */
	tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(roleid));
	if (HeapTupleIsValid(tup))
	{
		bool		isnull;
		Datum		d;

		d = SysCacheGetAttr(AUTHOID, tup, Anum_pg_authid_rolpassword, &isnull);
		if (!isnull)
		{
			char	   *cur = TextDatumGetCString(d);

			reused = ppp_matches_verifier(username, password, cur);
			pfree(cur);
		}
		ReleaseSysCache(tup);
	}
	if (reused)
		return true;

	values[0] = ObjectIdGetDatum(roleid);
	values[1] = Int32GetDatum(p->history_days);
	values[2] = Int32GetDatum(p->history_count);
	values[3] = CStringGetTextDatum(username);

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT verifier FROM " PPP_SCHEMA ".password_history "
								"WHERE (role_oid = $1 OR role_name = $4) "
								"AND ($2 <= 0 OR changed_at > pg_catalog.now() - pg_catalog.make_interval(days => $2)) "
								"ORDER BY changed_at DESC LIMIT $3",
								4, argtypes, values, NULL, true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: password_history lookup failed: %s",
			 SPI_result_code_string(ret));
	for (i = 0; i < SPI_processed && !reused; i++)
	{
		char	   *v = SPI_getvalue(SPI_tuptable->vals[i],
									 SPI_tuptable->tupdesc, 1);

		if (v != NULL)
			reused = ppp_matches_verifier(username, password, v);
	}
	ppp_spi_end(&st);

	return reused;
}

/*
 * Full evaluation shared by the hook and check_password() for a clear-text
 * password: complexity, minimum age, history.  Returns the code of the first
 * failed rule or NULL.
 */
static const char *
ppp_evaluate_plain(const char *username, Oid roleid, const char *password,
				   const pppProfile *p, bool skip_complexity, bool check_history)
{
	const char *code = NULL;

	if (!skip_complexity && !ppp_validate(username, password, p, &code))
		return code;
	if (!superuser() && ppp_min_age_violated(username, roleid, p))
		return "PPP-030";
	if (check_history && ppp_password_reused(username, roleid, password, p))
		return "PPP-031";
	return NULL;
}


/* ------------------------------------------------------------------------
 * Audit and rejection
 * ------------------------------------------------------------------------
 */

/*
 * Write a password_rejected audit row in a subtransaction.  Any failure is
 * downgraded to a LOG message so that it never hides the main error.
 *
 * Note: the ERROR raised right after aborts the enclosing transaction, which
 * also discards this row: the durable trace is the server log line written
 * by audit() (RAISE LOG), or by ppp_reject() when the audit failed.
 * Returns true if audit() succeeded.
 */
static bool
ppp_audit_rejection(const char *username, const char *code)
{
	MemoryContext oldcxt = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	pppSpiState st;
	volatile bool ok = true;

	if (IsInParallelMode())
		return false;

	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcxt);

	PG_TRY();
	{
		Oid			argtypes[2] = {TEXTOID, TEXTOID};
		Datum		values[2];
		int			ret;

		values[0] = CStringGetTextDatum(username);
		values[1] = CStringGetTextDatum(code);

		ppp_spi_begin(&st);
		ret = SPI_execute_with_args("SELECT " PPP_SCHEMA ".audit('password_rejected', $1, "
									"pg_catalog.jsonb_build_object('code', $2))",
									2, argtypes, values, NULL, false, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "audit() failed: %s", SPI_result_code_string(ret));
		ppp_spi_end(&st);

		ReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcxt);
		CurrentResourceOwner = oldowner;
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(oldcxt);
		edata = CopyErrorData();
		FlushErrorState();

		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcxt);
		CurrentResourceOwner = oldowner;
		ok = false;

		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "could not write audit event password_rejected for role \"%s\": %s",
						username, edata->message),
				 errhidestmt(true)));
		FreeErrorData(edata);
	}
	PG_END_TRY();

	return ok;
}

/*
 * Reject the password: log, audit, then ERROR.  The statement (which holds
 * the clear-text password) is hidden from the server log.
 */
static void
ppp_reject(const char *username, const char *code, const pppProfile *p,
		   bool audit)
{
	char	   *msg;
	char	   *detail;
	char	   *hint;

	ppp_describe(code, p, &msg, &detail, &hint);

	/* audit() logs the event itself; log here when not called or failed */
	if (!(audit && ppp_audit_rejection(username, code)) && ppp_log_events)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "password_rejected role=\"%s\" code=%s",
						username, code),
				 errhidestmt(true)));

	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PASSWORD),
			 errmsg("%s: %s", code, msg),
			 detail ? errdetail("%s", detail) : 0,
			 hint ? errhint("%s", hint) : 0,
			 errhidestmt(true)));
}

/* Record the accepted verifier through pass_policy.record_password_change */
static void
ppp_record_change(const char *username, const char *verifier)
{
	pppSpiState st;
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = CStringGetTextDatum(username);
	values[1] = CStringGetTextDatum(verifier);

	ppp_spi_begin(&st);
	ret = SPI_execute_with_args("SELECT " PPP_SCHEMA ".record_password_change($1, $2)",
								2, argtypes, values, NULL, false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: record_password_change() failed: %s",
			 SPI_result_code_string(ret));
	ppp_spi_end(&st);
}


/* ------------------------------------------------------------------------
 * check_password_hook
 * ------------------------------------------------------------------------
 */
static void
ppp_apply_policy(const char *username, const char *shadow_pass,
				 PasswordType password_type)
{
	pppProfile	prof;
	Oid			roleid;
	char	   *verifier;
	const char *code;

	/* step 1 */
	if (!ppp_enabled || ppp_role_is_exempt(username))
		return;

	/* step 2: where is the extension? */
	if (!ppp_schema_exists())
	{
		char	   *dbname = get_database_name(MyDatabaseId);
		bool		in_ppp_db = (dbname != NULL && ppp_database != NULL &&
								 strcmp(dbname, ppp_database) == 0);

		if (!in_ppp_db && ppp_enforce_database)
		{
			memset(&prof, 0, sizeof(prof));
			prof.name = "?";
			ppp_reject(username, "PPP-003", &prof, false);
		}

		if (!ppp_missing_schema_warned)
		{
			if (in_ppp_db)
				ereport(WARNING,
						(errmsg("pg_pass_policy: extension is not installed in database \"%s\", password policy not applied",
								dbname),
						 errhint("Run CREATE EXTENSION pg_pass_policy in this database.")));
			else
				ereport(WARNING,
						(errmsg("pg_pass_policy: password policy not applied outside database \"%s\"",
								ppp_database)));
			ppp_missing_schema_warned = true;
		}
		return;
	}

	ppp_load_effective_profile(username, &prof);
	roleid = get_role_oid(username, true);

	if (password_type != PASSWORD_TYPE_PLAINTEXT)
	{
		/* step 3: pre-hashed password, complexity cannot be checked */
		if (prof.reject_prehashed)
			ppp_reject(username, "PPP-001", &prof, true);
		if (password_type == PASSWORD_TYPE_MD5 && ppp_require_scram)
			ppp_reject(username, "PPP-002", &prof, true);
		if (!superuser() && ppp_min_age_violated(username, roleid, &prof))
			ppp_reject(username, "PPP-030", &prof, true);
		verifier = pstrdup(shadow_pass);
	}
	else
	{
		if (ppp_require_scram && Password_encryption == PASSWORD_TYPE_MD5)
			ppp_reject(username, "PPP-002", &prof, true);

		/* steps 4 to 6 */
		code = ppp_evaluate_plain(username, roleid, shadow_pass, &prof,
								  ppp_superuser_bypass && superuser(), true);
		if (code != NULL)
			ppp_reject(username, code, &prof, true);

		/* step 7 */
		verifier = encrypt_password(PASSWORD_TYPE_SCRAM_SHA_256, username,
									shadow_pass);
	}

	/* step 8 */
	ppp_record_change(username, verifier);
	pfree(verifier);
}

static void
ppp_check_password_hook(const char *username, const char *shadow_pass,
						PasswordType password_type, Datum validuntil_time,
						bool validuntil_null)
{
	bool		save_in_hook = ppp_in_hook;
	Oid			save_userid;
	int			save_sec_context;

	GetUserIdAndSecContext(&save_userid, &save_sec_context);

	/* steps 1 to 8 */
	ppp_in_hook = true;
	PG_TRY();
	{
		ppp_apply_policy(username, shadow_pass, password_type);
	}
	PG_FINALLY();
	{
		/* also restore the identity changed by ppp_spi_begin() on error */
		ppp_in_hook = save_in_hook;
		SetUserIdAndSecContext(save_userid, save_sec_context);
	}
	PG_END_TRY();

	/* step 9 */
	if (prev_check_password_hook)
		prev_check_password_hook(username, shadow_pass, password_type,
								 validuntil_time, validuntil_null);
}

void
ppp_policy_init(void)
{
	prev_check_password_hook = check_password_hook;
	check_password_hook = ppp_check_password_hook;
}


/* ------------------------------------------------------------------------
 * SQL functions
 * ------------------------------------------------------------------------
 */

static void
ppp_require_schema(void)
{
	if (!ppp_schema_exists())
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_pass_policy is not installed in this database")));
}

/*
 * pass_policy.check_password(role text, password text) RETURNS text
 *
 * NULL if the password complies with the effective profile of the role,
 * otherwise "PPP-0xx: reason".  No side effect, no audit.
 *
 * The history (and current password) comparison is only done when the
 * caller is a superuser or the role itself, so that the function cannot be
 * used as an oracle on another role's passwords.
 */
Datum
ppp_check_password(PG_FUNCTION_ARGS)
{
	char	   *username;
	text	   *pwtext;
	char	   *password;
	pppProfile	prof;
	Oid			roleid;
	const char *code = NULL;
	char	   *msg;
	char	   *detail;
	char	   *hint;
	char	   *result;
	bool		may_check_history;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();

	ppp_require_schema();

	username = text_to_cstring(PG_GETARG_TEXT_PP(0));
	pwtext = PG_GETARG_TEXT_PP(1);
	password = text_to_cstring(pwtext);

	ppp_load_effective_profile(username, &prof);
	roleid = get_role_oid(username, true);
	may_check_history = superuser() ||
		(OidIsValid(roleid) && roleid == GetUserId());

	switch (get_password_type(password))
	{
		case PASSWORD_TYPE_PLAINTEXT:
			if (ppp_require_scram && Password_encryption == PASSWORD_TYPE_MD5)
				code = "PPP-002";
			else
				code = ppp_evaluate_plain(username, roleid, password, &prof,
										  false, may_check_history);
			break;
		case PASSWORD_TYPE_MD5:
			if (prof.reject_prehashed)
				code = "PPP-001";
			else if (ppp_require_scram)
				code = "PPP-002";
			break;
		default:
			if (prof.reject_prehashed)
				code = "PPP-001";
			break;
	}

	ppp_secure_zero(password, strlen(password));
	pfree(password);
	/* wipe the detoasted copy, if any (never the caller's datum) */
	if ((Pointer) pwtext != PG_GETARG_POINTER(1))
		ppp_secure_zero(VARDATA_ANY(pwtext), VARSIZE_ANY_EXHDR(pwtext));

	if (code == NULL)
		PG_RETURN_NULL();

	ppp_describe(code, &prof, &msg, &detail, &hint);
	result = detail ? psprintf("%s: %s. %s", code, msg, detail)
		: psprintf("%s: %s", code, msg);
	PG_RETURN_TEXT_P(cstring_to_text(result));
}

/* Uniform random integer in [0, n) from pg_strong_random (rejection sampling) */
static uint32
ppp_random_uniform(uint32 n)
{
	uint32		r;
	uint32		limit;

	Assert(n > 0);
	limit = PG_UINT32_MAX - (PG_UINT32_MAX % n);
	do
	{
		if (!pg_strong_random(&r, sizeof(r)))
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pg_pass_policy: could not generate random values")));
	} while (r >= limit);
	return r % n;
}

static char
ppp_random_char(const char *alphabet)
{
	return alphabet[ppp_random_uniform((uint32) strlen(alphabet))];
}

/*
 * pass_policy.generate_password(length int DEFAULT 24, profile text
 * DEFAULT NULL) RETURNS text
 *
 * Builds a password from pg_strong_random only, satisfying the class minima
 * of the given profile (or "default"), then shuffles it (Fisher-Yates).
 */
Datum
ppp_generate_password(PG_FUNCTION_ARGS)
{
	int32		length;
	const char *profname;
	pppProfile	prof;
	pppProfile	genprof;
	int			need_lower,
				need_upper,
				need_digit,
				need_special;
	int			nclasses_forced;
	char	   *buf;
	text	   *result;
	int			tries;

	length = PG_ARGISNULL(0) ? 24 : PG_GETARG_INT32(0);
	if (length < PPP_GEN_MIN_LENGTH || length > PPP_GEN_MAX_LENGTH)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("password length must be between %d and %d",
						PPP_GEN_MIN_LENGTH, PPP_GEN_MAX_LENGTH)));

	ppp_require_schema();
	profname = PG_ARGISNULL(1) ? "default" : text_to_cstring(PG_GETARG_TEXT_PP(1));
	ppp_load_named_profile(profname, &prof);

	if (length < prof.min_length ||
		(prof.max_length > 0 && length > prof.max_length))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("password length %d does not comply with profile \"%s\"",
						length, prof.name),
				 errdetail("The profile requires between %d and %d characters.",
						   prof.min_length, prof.max_length)));

	need_lower = Max(prof.min_lower, 1);
	need_upper = Max(prof.min_upper, 1);
	need_digit = Max(prof.min_digit, 1);
	need_special = Max(prof.min_special, 0);

	/*
	 * Specials are only forced when the profile asks for them, or when the
	 * three other classes are not enough to reach min_classes.
	 */
	nclasses_forced = 3 + (need_special > 0);
	if (nclasses_forced < prof.min_classes)
		need_special = 1;

	if (need_lower + need_upper + need_digit + need_special > length)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("password length %d is too small for the character class minima of profile \"%s\"",
						length, prof.name)));

	/* the generated password is re-validated without username/dictionary */
	genprof = prof;
	genprof.reject_username = false;
	genprof.reject_dictionary = false;

	buf = palloc(length + 1);
	for (tries = 0;; tries++)
	{
		const char *code;
		int			pos = 0;
		int			i;
		char	   *all;

		for (i = 0; i < need_lower; i++)
			buf[pos++] = ppp_random_char(ppp_alpha_lower);
		for (i = 0; i < need_upper; i++)
			buf[pos++] = ppp_random_char(ppp_alpha_upper);
		for (i = 0; i < need_digit; i++)
			buf[pos++] = ppp_random_char(ppp_alpha_digit);
		for (i = 0; i < need_special; i++)
			buf[pos++] = ppp_random_char(ppp_alpha_special);

		all = psprintf("%s%s%s%s", ppp_alpha_lower, ppp_alpha_upper,
					   ppp_alpha_digit, ppp_alpha_special);
		while (pos < length)
			buf[pos++] = ppp_random_char(all);
		pfree(all);
		buf[length] = '\0';

		/* Fisher-Yates shuffle */
		for (i = length - 1; i > 0; i--)
		{
			int			j = (int) ppp_random_uniform((uint32) i + 1);
			char		tmp = buf[i];

			buf[i] = buf[j];
			buf[j] = tmp;
		}

		if (ppp_validate("", buf, &genprof, &code))
			break;
		if (tries >= PPP_GEN_MAX_TRIES)
		{
			ppp_secure_zero(buf, length);
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pg_pass_policy: could not generate a password compliant with profile \"%s\" (%s)",
							prof.name, code)));
		}
	}

	result = cstring_to_text_with_len(buf, length);
	ppp_secure_zero(buf, length + 1);
	pfree(buf);

	PG_RETURN_TEXT_P(result);
}

/*
 * pass_policy._in_password_hook() RETURNS bool
 *
 * True only while this backend is executing the pg_pass_policy
 * check_password_hook (addition to SPEC 4, used by the SQL guards of
 * record_password_change() and audit()).
 */
Datum
ppp_in_password_hook(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(ppp_in_hook);
}
