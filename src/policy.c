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

#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <wctype.h>

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
PG_FUNCTION_INFO_V1(ppp_generate_password_for);
PG_FUNCTION_INFO_V1(ppp_in_password_hook);
PG_FUNCTION_INFO_V1(ppp_record_done);

static check_password_hook_type prev_check_password_hook = NULL;

/*
 * WARNING "policy not applied" (extension not installed here, or outside
 * pg_pass_policy.database) emitted once per session, with one flag per
 * source: the hook (password changes) and generate_password().  Separate
 * flags, so that a generate_password() called first does not silence the
 * WARNING of a password change that the policy does not check.
 */
static bool ppp_hook_not_applied_warned = false;
static bool ppp_generate_not_applied_warned = false;

/*
 * WARNING "password policy not applied outside database", at most once per
 * session for the flag *warned (see above).
 */
static void
ppp_warn_policy_not_applied(bool *warned)
{
	if (*warned)
		return;
	ereport(WARNING,
			(errmsg("pg_pass_policy: password policy not applied outside database \"%s\"",
					ppp_database),
			 errhidestmt(true),
			 errhidecontext(true)));
	*warned = true;
}

/*
 * True while this backend runs the password hook: lets the SQL side
 * (record_password_change()) accept calls coming from the hook.
 */
static bool ppp_in_hook = false;

/* Generated passwords: lengths accepted by generate_password() */
#define PPP_GEN_MIN_LENGTH	8
/* PPP_GEN_MAX_LENGTH: also pass_policy._max_generated_length() (SQL script) */
#define PPP_GEN_MAX_LENGTH	512
#define PPP_GEN_MAX_TRIES	100

/* Alphabet without ambiguous characters 0 O 1 l I | */
#define PPP_ALPHA_LOWER		"abcdefghijkmnopqrstuvwxyz"
#define PPP_ALPHA_UPPER		"ABCDEFGHJKLMNPQRSTUVWXYZ"
#define PPP_ALPHA_DIGIT		"23456789"
#define PPP_ALPHA_SPECIAL	"!#%()*+,-./:;=?@[]^_{}~"

static const char ppp_alpha_lower[] = PPP_ALPHA_LOWER;
static const char ppp_alpha_upper[] = PPP_ALPHA_UPPER;
static const char ppp_alpha_digit[] = PPP_ALPHA_DIGIT;
static const char ppp_alpha_special[] = PPP_ALPHA_SPECIAL;
static const char ppp_alpha_all[] = PPP_ALPHA_LOWER PPP_ALPHA_UPPER
PPP_ALPHA_DIGIT PPP_ALPHA_SPECIAL;

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

/*
 * State saved while running SPI as the bootstrap superuser.  outer_cxt is
 * the memory context current before SPI_connect(): what must survive
 * SPI_finish() (profile strings, results) is allocated there.
 */
typedef struct pppSpiState
{
	Oid			save_userid;
	int			save_sec_context;
	int			save_nestlevel;
	MemoryContext outer_cxt;
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
 *
 * One such session covers a whole entry point (password hook,
 * check_password(), generate_password()): superuser() and GetUserId() of
 * the caller must therefore be read BEFORE calling this.  On error, the
 * entry point restores the identity itself and re-throws through
 * ppp_rethrow_hidden(); the GUC level and the SPI connection are then
 * released by the (sub)transaction abort.
 */
static void
ppp_spi_begin(pppSpiState *st)
{
	st->outer_cxt = CurrentMemoryContext;
	GetUserIdAndSecContext(&st->save_userid, &st->save_sec_context);
	SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID,
						   st->save_sec_context | SECURITY_LOCAL_USERID_CHANGE |
						   SECURITY_RESTRICTED_OPERATION);
	st->save_nestlevel = NewGUCNestLevel();
	(void) set_config_option("search_path", "pg_catalog, pg_temp",
							 PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);

	/*
	 * Messages raised on the SQL side (e.g. RAISE LOG in audit(), or an
	 * ERROR from record_password_change()) must carry neither the STATEMENT
	 * nor the CONTEXT: when the hook runs inside an EXECUTE (rotate_password
	 * -> _set_password), both would hold ALTER ROLE ... PASSWORD 'clear text'.
	 * Both settings are popped by ppp_spi_end() / AtEOXact_GUC.
	 */
	(void) set_config_option("log_min_error_statement", "panic",
							 PGC_SUSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);
	(void) set_config_option("log_error_verbosity", "terse",
							 PGC_SUSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);

	/*
	 * auto_explain (log_nested_statements = on) would log the parameters of
	 * the nested statements run here, record_password_change($1, $2) in
	 * particular, whose $2 is the SCRAM verifier of the new password
	 * (offline-cracking material).  Disabled for the duration of the SPI
	 * call when the module is loaded.
	 */
	if (GetConfigOption("auto_explain.log_min_duration", true, false) != NULL)
		(void) set_config_option("auto_explain.log_min_duration", "-1",
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

/*
 * Re-throw the error being handled with its STATEMENT and CONTEXT hidden.
 *
 * Called from the PG_CATCH() of the entry points that receive a clear-text
 * password (the hook, check_password()) or run under the elevated SPI
 * session.  The GUC guard of ppp_spi_begin() (log_min_error_statement =
 * panic) only protects the messages emitted while it is active: an ERROR is
 * written to the server log by the outermost handler, after this function
 * has returned, when the statement text (ALTER ROLE ... PASSWORD 'x', or
 * SELECT check_password('r', 'x')) would otherwise be printed.  Marking the
 * error itself covers every ERROR raised below, including those of
 * PostgreSQL functions (get_role_oid, encrypt_password, SPI...) that do not
 * call errhidestmt().
 */
static void
ppp_rethrow_hidden(MemoryContext cxt)
{
	ErrorData  *edata;

	MemoryContextSwitchTo(cxt);
	edata = CopyErrorData();
	FlushErrorState();
	edata->hide_stmt = true;
	edata->hide_ctx = true;
	ReThrowError(edata);
}

/*
 * PPP-004: the extension is present in this database but cannot be trusted
 * (schema re-owned by a non-superuser, owner demoted, objects outside
 * PPP_SCHEMA).  Applying no policy at all would silently fail open, and
 * running its SQL as superuser would hand that owner superuser rights:
 * refuse explicitly.
 */
static void
ppp_untrusted_error(Oid nspowner)
{
	char	   *detail = ppp_untrusted_detail(nspowner);

	ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
			 errmsg("PPP-004: pg_pass_policy schema is not trusted"),
			 errdetail_internal("%s", detail),
			 errhint("A superuser must own schema \"" PPP_SCHEMA "\" (ALTER SCHEMA " PPP_SCHEMA " OWNER TO a superuser)."),
			 errhidestmt(true),
			 errhidecontext(true)));
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
	return ppp_spi_get_int32(tup, SPI_tuptable->tupdesc, ppp_col(colname),
							 defval);
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
 * Runs inside the SPI session of the caller; strings are allocated in cxt.
 */
static void
ppp_load_effective_profile(const char *rolename, pppProfile *p,
						   MemoryContext cxt)
{
	Oid			argtypes[1] = {NAMEOID};
	Datum		values[1];
	int			ret;

	values[0] = DirectFunctionCall1(namein, CStringGetDatum(rolename));

	ret = SPI_execute_with_args("SELECT * FROM " PPP_SCHEMA ".effective_profile($1)",
								1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: effective_profile() failed: %s",
			 SPI_result_code_string(ret));
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pg_pass_policy: no effective profile for role \"%s\"",
						rolename),
				 errhidestmt(true),
				 errhidecontext(true)));
	ppp_profile_from_spi(p, cxt);
}

/* Load a profile by name (generate_password), inside the caller's SPI session */
static void
ppp_load_named_profile(const char *profname, pppProfile *p, MemoryContext cxt)
{
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;

	values[0] = CStringGetTextDatum(profname);

	ret = SPI_execute_with_args("SELECT * FROM " PPP_SCHEMA ".profile WHERE name = $1",
								1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: profile lookup failed: %s",
			 SPI_result_code_string(ret));
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pg_pass_policy: profile \"%s\" does not exist", profname),
				 errhidestmt(true),
				 errhidecontext(true)));
	ppp_profile_from_spi(p, cxt);
}


/* ------------------------------------------------------------------------
 * Complexity checks (SPEC 6.2 step 4)
 * ------------------------------------------------------------------------
 */

/*
 * Lower-case a secret; the caller must ppp_secure_zero() the result.
 *
 * Same result as str_tolower(s, len, DEFAULT_COLLATION_OID) with the libc
 * provider, but without leaving an unwiped copy of the password behind:
 * str_tolower() converts multi-byte strings through a wchar_t workspace
 * that it pfree()s without clearing.  Here the workspace is ours and wiped.
 *   - single-byte encoding, or LC_CTYPE = C: converted in place (ASCII only
 *     under C, like the server);
 *   - UTF-8 with another LC_CTYPE: pg_wchar (= Unicode code point) +
 *     towlower() on the backend's LC_CTYPE (datctype), the same calls the
 *     server makes for the default libc collation.  With an ICU default
 *     collation, ICU special casing is not applied (documented, SPEC 8.5);
 *   - other multi-byte encodings: str_tolower() (residual copy, documented).
 */
static bool
ppp_ctype_is_c(void)
{
	const char *ctype = setlocale(LC_CTYPE, NULL);

	return ctype == NULL || strcmp(ctype, "C") == 0 || strcmp(ctype, "POSIX") == 0;
}

static char *
ppp_lower(const char *s)
{
	size_t		len = strlen(s);
	bool		ctype_c = ppp_ctype_is_c();
	char	   *result;

	if (pg_database_encoding_max_length() == 1 || ctype_c)
	{
		char	   *p;

		result = pstrdup(s);
		for (p = result; *p; p++)
			*p = ctype_c ? pg_tolower((unsigned char) *p)
				: (char) tolower((unsigned char) *p);
		return result;
	}

	if (GetDatabaseEncoding() == PG_UTF8)
	{
		size_t		wsize = (len + 1) * sizeof(pg_wchar);
		pg_wchar   *ws = palloc(wsize);
		int			nchars = pg_mb2wchar_with_len(s, ws, (int) len);
		int			i;

		for (i = 0; i < nchars; i++)
			ws[i] = (pg_wchar) towlower((wint_t) ws[i]);
		result = palloc((size_t) nchars * pg_database_encoding_max_length() + 1);
		pg_wchar2mb_with_len(ws, result, nchars);
		ppp_secure_zero(ws, wsize);
		pfree(ws);
		return result;
	}

	return str_tolower(s, len, DEFAULT_COLLATION_OID);
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
 * pass_policy.dictionary?
 *
 * Only the SHA-256 digest of the lower-cased password is sent to SQL, as a
 * bound parameter compared with the generated column word_sha256 (unique
 * index): the clear text never leaves this file, and nothing but the
 * matching row is read.  The digest is unsalted, but it is never stored nor
 * logged (bound parameters of SPI statements are not logged by
 * log_statement / log_parameter_max_length, auto_explain is silenced by
 * ppp_spi_begin()), and the digest of a word that IS in the dictionary
 * reveals nothing (the word is public).
 *
 * sha256() is called through the fmgr interface (sha256_bytea, available
 * with the same signature on every supported version) rather than through
 * common/cryptohash.h.  Must run inside the SPI session of the caller.
 */
static bool
ppp_in_dictionary(const char *lower_pw)
{
	size_t		len = strlen(lower_pw);
	bytea	   *volatile input;
	bytea	   *volatile digest = NULL;
	Oid			argtypes[1] = {BYTEAOID};
	Datum		values[1];
	int			ret;
	volatile bool found = false;

	input = (bytea *) palloc(VARHDRSZ + len);
	SET_VARSIZE(input, VARHDRSZ + len);
	memcpy(VARDATA(input), lower_pw, len);

	PG_TRY();
	{
		digest = DatumGetByteaPP(DirectFunctionCall1(sha256_bytea,
													 PointerGetDatum(input)));
		values[0] = PointerGetDatum(digest);
		ret = SPI_execute_with_args("SELECT 1 FROM " PPP_SCHEMA ".dictionary "
									"WHERE word_sha256 = $1",
									1, argtypes, values, NULL, true, 1);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "pg_pass_policy: dictionary lookup failed: %s",
				 SPI_result_code_string(ret));
		found = (SPI_processed > 0);
	}
	PG_FINALLY();
	{
		ppp_secure_zero(VARDATA(input), len);
		pfree(input);
		if (digest != NULL)
		{
			ppp_secure_zero(VARDATA_ANY(digest), VARSIZE_ANY_EXHDR(digest));
			pfree(digest);
		}
	}
	PG_END_TRY();

	return found;
}

/*
 * Non-ASCII code points refused by PPP-020 in a UTF8 database: the Unicode
 * general categories Cc (C1 controls), Cf (format: zero-width characters,
 * bidirectional marks, BOM, tags...), Zs (spaces other than U+0020: U+00A0
 * no-break space, U+3000...), Zl (U+2028) and Zp (U+2029), Unicode 15.
 * They are invisible or ambiguous in a password and would otherwise count
 * as "special" characters.  Explicit list, sorted, no dependency on ICU
 * or on the server locale.
 */
static const struct
{
	pg_wchar	first;
	pg_wchar	last;
}			ppp_invisible_ranges[] =
{
	{0x0080, 0x00A0},			/* C1 controls (Cc), U+00A0 (Zs) */
	{0x00AD, 0x00AD},			/* soft hyphen (Cf) */
	{0x0600, 0x0605},			/* Arabic number signs (Cf) */
	{0x061C, 0x061C},			/* Arabic letter mark (Cf) */
	{0x06DD, 0x06DD},
	{0x070F, 0x070F},
	{0x0890, 0x0891},
	{0x08E2, 0x08E2},
	{0x1680, 0x1680},			/* Ogham space mark (Zs) */
	{0x180E, 0x180E},			/* Mongolian vowel separator (Cf) */
	{0x2000, 0x200F},			/* spaces (Zs), U+200B..U+200F (Cf) */
	{0x2028, 0x202F},			/* U+2028 (Zl), U+2029 (Zp), bidi (Cf),
								 * U+202F (Zs) */
	{0x205F, 0x2064},			/* U+205F (Zs), word joiner... (Cf) */
	{0x2066, 0x206F},			/* bidi isolates... (Cf) */
	{0x3000, 0x3000},			/* ideographic space (Zs) */
	{0xFEFF, 0xFEFF},			/* BOM / zero-width no-break space (Cf) */
	{0xFFF9, 0xFFFB},			/* interlinear annotation (Cf) */
	{0x110BD, 0x110BD},
	{0x110CD, 0x110CD},
	{0x13430, 0x1343F},
	{0x1BCA0, 0x1BCA3},
	{0x1D173, 0x1D17A},
	{0xE0001, 0xE0001},			/* language tag (Cf) */
	{0xE0020, 0xE007F}			/* tag characters (Cf) */
};

/*
 * Code point of the UTF-8 sequence of len (2 to 4) bytes at s.  The string
 * is valid in the server encoding (text input and the parser verify it).
 */
static pg_wchar
ppp_utf8_code_point(const unsigned char *s, int len)
{
	switch (len)
	{
		case 2:
			return ((pg_wchar) (s[0] & 0x1F) << 6) | (s[1] & 0x3F);
		case 3:
			return ((pg_wchar) (s[0] & 0x0F) << 12) |
				((pg_wchar) (s[1] & 0x3F) << 6) | (s[2] & 0x3F);
		case 4:
			return ((pg_wchar) (s[0] & 0x07) << 18) |
				((pg_wchar) (s[1] & 0x3F) << 12) |
				((pg_wchar) (s[2] & 0x3F) << 6) | (s[3] & 0x3F);
		default:
			return 0;
	}
}

/* Is a non-ASCII code point refused by PPP-020 (ppp_invisible_ranges)? */
static bool
ppp_is_invisible(pg_wchar cp)
{
	int			lo = 0;
	int			hi = lengthof(ppp_invisible_ranges) - 1;

	while (lo <= hi)
	{
		int			mid = (lo + hi) / 2;

		if (cp < ppp_invisible_ranges[mid].first)
			hi = mid - 1;
		else if (cp > ppp_invisible_ranges[mid].last)
			lo = mid + 1;
		else
			return true;
	}
	return false;
}

/*
 * Validate the clear-text password against the complexity rules of the
 * profile, in the order of SPEC 6.2 step 4.  Returns true if the password is
 * acceptable; otherwise sets *code to a static "PPP-0xx" string.
 *
 * The dictionary lookup runs in the SPI session of the caller.
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
	bool		utf8 = (GetDatabaseEncoding() == PG_UTF8);

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
		else if (utf8 &&
				 ppp_is_invisible(ppp_utf8_code_point((const unsigned char *) c, l)))
			nonprintable = true;	/* Unicode control, format or space */
		else
			nspecial++;			/* any other non-ASCII character is
								 * "special" (in a UTF8 database; every
								 * non-ASCII character in other encodings) */

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
		char	   *volatile lower_pw = ppp_lower(password);
		volatile bool bad = false;

		/*
		 * The dictionary lookup goes through SPI and may raise an ERROR:
		 * the lower-cased copy of the password is wiped whatever happens.
		 */
		PG_TRY();
		{
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
		}
		PG_FINALLY();
		{
			ppp_secure_zero(lower_pw, strlen(lower_pw));
			pfree(lower_pw);
		}
		PG_END_TRY();

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
		*detail = pstrdup("The password must not contain control, format or invisible space characters, nor start or end with a space.");
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
		*detail = psprintf("The password must differ from the last %d passwords (current one included).",
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
 * applicable when the password was force-expired (must_change), nor to a
 * role that does not exist yet (CREATE ROLE).
 *
 * The role_state lookup is by OID only: a role_state row carrying the same
 * name but another OID can only belong to a dropped role (stale until the
 * next run_maintenance()), whose date must not apply to a re-created role.
 * A role created by CREATE ROLE ... PASSWORD has no role_state row until
 * the next run_maintenance(), only a password_history row with role_oid IS
 * NULL: the date of the most recent such row (by name) is used too, so that
 * min_age does not depend on whether the maintenance already ran.
 * Runs inside the SPI session of the caller.
 */
static bool
ppp_min_age_violated(const char *username, Oid roleid, const pppProfile *p)
{
	Oid			argtypes[3] = {OIDOID, INTERVALOID, TEXTOID};
	Datum		values[3];
	int			ret;
	bool		violated = false;

	if (!OidIsValid(roleid) || p->min_age_null)
		return false;

	values[0] = ObjectIdGetDatum(roleid);
	values[1] = p->min_age;
	values[2] = CStringGetTextDatum(username);

	/* greatest() ignores NULLs; a NULL result means "not violated" */
	ret = SPI_execute_with_args("SELECT NOT coalesce(s.must_change, false) "
								"AND (pg_catalog.now() - GREATEST(s.password_changed_at, h.changed_at)) < $2 "
								"FROM (SELECT pg_catalog.max(h1.changed_at) AS changed_at "
								"FROM " PPP_SCHEMA ".password_history h1 "
								"WHERE h1.role_oid IS NULL AND h1.role_name = $3) h "
								"LEFT JOIN " PPP_SCHEMA ".role_state s ON s.role_oid = $1",
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
 * (not older than history_days).  The most recent history row normally is
 * the current password: "history_count" passwords, current one included.
 *
 * Existing role: rows of its OID, plus the rows not yet mapped to an OID
 * (role_oid IS NULL) under its name, written by CREATE ROLE ... PASSWORD and
 * mapped only by the next run_maintenance().  Rows of a dropped role of the
 * same name (another OID, not yet purged) are never used: they must not be
 * resurrected for a re-created role.  Role not created yet (CREATE ROLE ...
 * PASSWORD): only the rows with role_oid IS NULL, by name.
 * Runs inside the SPI session of the caller.
 */
static bool
ppp_password_reused(const char *username, Oid roleid, const char *password,
					const pppProfile *p)
{
	Oid			argtypes[4] = {INT4OID, INT4OID, TEXTOID, OIDOID};
	Datum		values[4];
	int			ret;
	bool		reused = false;
	uint64		i;

	if (p->history_count <= 0)
		return false;

	if (OidIsValid(roleid))
	{
		HeapTuple	tup;

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
	}

	values[0] = Int32GetDatum(p->history_days);
	values[1] = Int32GetDatum(p->history_count);
	values[2] = CStringGetTextDatum(username);
	if (OidIsValid(roleid))
	{
		values[3] = ObjectIdGetDatum(roleid);
		ret = SPI_execute_with_args("SELECT verifier FROM " PPP_SCHEMA ".password_history "
									"WHERE (role_oid = $4 OR (role_oid IS NULL AND role_name = $3)) "
									"AND ($1 <= 0 OR changed_at > pg_catalog.now() - pg_catalog.make_interval(days => $1)) "
									"ORDER BY changed_at DESC, id DESC LIMIT $2",
									4, argtypes, values, NULL, true, 0);
	}
	else
	{
		ret = SPI_execute_with_args("SELECT verifier FROM " PPP_SCHEMA ".password_history "
									"WHERE role_oid IS NULL AND role_name = $3 "
									"AND ($1 <= 0 OR changed_at > pg_catalog.now() - pg_catalog.make_interval(days => $1)) "
									"ORDER BY changed_at DESC, id DESC LIMIT $2",
									3, argtypes, values, NULL, true, 0);
	}
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

	return reused;
}

/*
 * May the minimum age and history of the role be checked for this caller?
 * caller is the user id and caller_is_super its superuser() status, both
 * read before any elevation; roleid is the target role (InvalidOid when it
 * does not exist yet: the history is then checked by name, as CREATE ROLE
 * ... PASSWORD does).  Shared by the hook and check_password(): a caller
 * who may not change the role's password must not learn anything about its
 * passwords or the date of its last change (SPEC 6.2, step 5).
 */
static bool
ppp_may_check_history(Oid caller, bool caller_is_super, Oid roleid)
{
	return caller_is_super || !OidIsValid(roleid) || roleid == caller ||
		PPP_MAY_SET_PASSWORD_OF(caller, roleid);
}

/*
 * Full evaluation shared by the hook and check_password() for a clear-text
 * password: complexity, minimum age, history.  Returns the code of the first
 * failed rule or NULL.
 *
 * caller_is_super is the superuser() status of the caller, read before the
 * SPI session switched to the bootstrap superuser.  check_history covers
 * both the minimum age and the history: check_password() disables them when
 * the caller may not learn anything about another role's passwords or
 * password change date.
 */
static const char *
ppp_evaluate_plain(const char *username, Oid roleid, const char *password,
				   const pppProfile *p, bool skip_complexity, bool check_history,
				   bool caller_is_super)
{
	const char *code = NULL;

	if (!skip_complexity && !ppp_validate(username, password, p, &code))
		return code;
	if (check_history && !caller_is_super && ppp_min_age_violated(username, roleid, p))
		return "PPP-030";
	if (check_history && ppp_password_reused(username, roleid, password, p))
		return "PPP-031";
	return NULL;
}

/*
 * Evaluation of a candidate password of any type, shared by the hook and
 * check_password() so that the function answers what the hook would
 * (SPEC 6.2, steps 3 to 6).  password_type is the type PostgreSQL computed
 * (get_password_type()).  Returns the code of the first failed rule or NULL.
 *
 * - pre-hashed: PPP-001 (reject_prehashed), PPP-002 (MD5 with require_scram),
 *   then the minimum age (PPP-030) when check_history and the caller is not
 *   a superuser; complexity and history cannot be checked on a verifier;
 * - clear text: PPP-002 when password_encryption is md5 with require_scram,
 *   then complexity (skipped when bypass_complexity), minimum age and
 *   history (ppp_evaluate_plain()).
 *
 * bypass_complexity is superuser_bypass applied to a superuser caller: the
 * hook passes it, check_password() never does (it answers for the profile
 * of the role, whoever calls it).
 */
static const char *
ppp_evaluate_password(const char *username, Oid roleid, const char *password,
					  PasswordType password_type, const pppProfile *p,
					  bool check_history, bool caller_is_super,
					  bool bypass_complexity)
{
	if (password_type != PASSWORD_TYPE_PLAINTEXT)
	{
		if (p->reject_prehashed)
			return "PPP-001";
		if (password_type == PASSWORD_TYPE_MD5 && ppp_require_scram)
			return "PPP-002";
		if (check_history && !caller_is_super &&
			ppp_min_age_violated(username, roleid, p))
			return "PPP-030";
		return NULL;
	}

	if (ppp_require_scram && Password_encryption == PASSWORD_TYPE_MD5)
		return "PPP-002";
	return ppp_evaluate_plain(username, roleid, password, p,
							  bypass_complexity, check_history,
							  caller_is_super);
}


/* ------------------------------------------------------------------------
 * Audit and rejection
 * ------------------------------------------------------------------------
 */

/*
 * Reject the password: log, then ERROR.  The statement (which holds the
 * clear-text password) and the context (which holds it too when the ALTER
 * ROLE is run through EXECUTE, as in rotate_password) are hidden from the
 * server log, here and again by ppp_rethrow_hidden() in the hook.
 *
 * The rejection is not written to audit_log: the ERROR raised right after
 * aborts the enclosing transaction, which would discard the row and its
 * NOTIFY anyway.  The durable trace is this LOG line, in the format of the
 * one written by _audit() for the other events (pg_pass_policy.log_events).
 */
static void
ppp_reject(const char *username, const char *code, const pppProfile *p)
{
	char	   *msg;
	char	   *detail;
	char	   *hint;

	ppp_describe(code, p, &msg, &detail, &hint);

	if (ppp_log_events)
		ereport(LOG,
				(errmsg(PPP_LOG_PREFIX "password_rejected role=%s {\"code\": \"%s\"}",
						username, code),
				 errhidestmt(true),
				 errhidecontext(true)));

	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PASSWORD),
			 errmsg("%s: %s", code, msg),
			 detail ? errdetail("%s", detail) : 0,
			 hint ? errhint("%s", hint) : 0,
			 errhidestmt(true),
			 errhidecontext(true)));
}

/*
 * Record the accepted verifier through pass_policy.record_password_change,
 * inside the SPI session of the hook.
 */
static void
ppp_record_change(const char *username, const char *verifier)
{
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = CStringGetTextDatum(username);
	values[1] = CStringGetTextDatum(verifier);

	ret = SPI_execute_with_args("SELECT " PPP_SCHEMA ".record_password_change($1, $2)",
								2, argtypes, values, NULL, false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pg_pass_policy: record_password_change() failed: %s",
			 SPI_result_code_string(ret));
	ppp_note_password_recorded(username);
}


/* ------------------------------------------------------------------------
 * Extension state (SPEC 6.2 step 2)
 * ------------------------------------------------------------------------
 */

/*
 * Where is the extension?  Catalog lookups only, no SPI: called BEFORE the
 * elevated SPI session is opened, which is only needed (and only allowed)
 * when the extension is installed and trusted.
 *
 * PPP_EXT_UNTRUSTED raises PPP-004.  PPP_EXT_ABSENT raises an ERROR when
 * absent_is_error (SQL functions of this file), otherwise it is returned
 * and handled by the caller (password hook: ppp_extension_absent()).
 * Returns PPP_EXT_TRUSTED or PPP_EXT_ABSENT.
 */
static pppExtensionState
ppp_require_extension(bool absent_is_error)
{
	Oid			nspowner;
	pppExtensionState state = ppp_extension_state(&nspowner);

	switch (state)
	{
		case PPP_EXT_TRUSTED:
			break;
		case PPP_EXT_UNTRUSTED:
			ppp_untrusted_error(nspowner);
			break;
		case PPP_EXT_ABSENT:
			if (absent_is_error)
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						 errmsg("pg_pass_policy is not installed in this database"),
						 errhidestmt(true),
						 errhidecontext(true)));
			break;
		default:
			elog(ERROR, "pg_pass_policy: unexpected extension state %d",
				 (int) state);
			break;
	}
	return state;
}


/* ------------------------------------------------------------------------
 * check_password_hook
 * ------------------------------------------------------------------------
 */

/*
 * Is the current database the one designated by pg_pass_policy.database?
 * Only that database holds the tables maintained by the worker (SPEC 5).
 */
static bool
ppp_in_policy_database(void)
{
	char	   *dbname = get_database_name(MyDatabaseId);

	return (dbname != NULL && ppp_database != NULL &&
			strcmp(dbname, ppp_database) == 0);
}

/*
 * Password change where the policy cannot be applied (SPEC 6.2 step 2):
 * either outside pg_pass_policy.database, whether or not the extension is
 * installed in the current database (in_ppp_db false), or in that database
 * while the extension is not installed there (in_ppp_db true).  Outside
 * that database: PPP-003 when enforce_database is on, otherwise a WARNING
 * once per session and the policy is not applied, even if the extension is
 * installed: its tables there would never be maintained by the worker.  No
 * SPI and no audit row.
 */
static void
ppp_policy_not_applicable(const char *username, bool in_ppp_db)
{
	if (!in_ppp_db && ppp_enforce_database)
	{
		pppProfile	prof;

		memset(&prof, 0, sizeof(prof));
		prof.name = "?";
		ppp_reject(username, "PPP-003", &prof);
	}

	if (!in_ppp_db)
		ppp_warn_policy_not_applied(&ppp_hook_not_applied_warned);
	else if (!ppp_hook_not_applied_warned)
	{
		ereport(WARNING,
				(errmsg("pg_pass_policy: extension is not installed in database \"%s\", password policy not applied",
						ppp_database),
				 errhint("Run CREATE EXTENSION pg_pass_policy in this database."),
				 errhidestmt(true),
				 errhidecontext(true)));
		ppp_hook_not_applied_warned = true;
	}
}

/*
 * check_password() and generate_password() outside pg_pass_policy.database:
 * the hook applies no policy there (PPP-003 or nothing), and the tables of
 * the extension, if installed, are not maintained by the worker.
 * always_error (check_password()): ERROR PPP-003 whatever enforce_database,
 * since an answer "compliant" would be meaningless.  Otherwise
 * (generate_password()): ERROR PPP-003 with enforce_database, else a
 * WARNING (once per session, flag separate from the hook's) and the caller goes on
 * (a random password harms nobody).
 */
static void
ppp_require_policy_database(bool always_error)
{
	char	   *msg;
	char	   *detail;
	char	   *hint;
	pppProfile	prof;

	if (ppp_in_policy_database())
		return;

	memset(&prof, 0, sizeof(prof));
	prof.name = "?";
	ppp_describe("PPP-003", &prof, &msg, &detail, &hint);
	if (always_error || ppp_enforce_database)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("PPP-003: %s", msg),
				 errhint("%s", hint),
				 errhidestmt(true),
				 errhidecontext(true)));
	/* once per session, flag of its own (not the hook's) */
	ppp_warn_policy_not_applied(&ppp_generate_not_applied_warned);
}

/*
 * Steps 3 to 8 of SPEC 6.2, run inside the single SPI session opened by the
 * hook once the extension is known to be installed and trusted (step 2).
 * caller_is_super is superuser() of the caller, roleid the OID of the
 * target role (InvalidOid for CREATE ROLE) and may_check_history whether
 * the caller may change its password; all three are read before that
 * session switched to the bootstrap superuser.  When may_check_history is
 * false, the minimum age and history checks are skipped silently: their
 * answer (PPP-030, PPP-031) would tell the caller something about the
 * passwords of a role he cannot manage, and PostgreSQL refuses the command
 * anyway.  The complexity checks only depend on the candidate password and
 * always run.
 */
static void
ppp_apply_policy(const char *username, const char *shadow_pass,
				 PasswordType password_type, bool caller_is_super,
				 Oid roleid, bool may_check_history, MemoryContext cxt)
{
	pppProfile	prof;
	char	   *verifier;
	const char *code;

	ppp_load_effective_profile(username, &prof, cxt);

	/* steps 3 to 6 (same evaluation as check_password()) */
	code = ppp_evaluate_password(username, roleid, shadow_pass, password_type,
								 &prof, may_check_history, caller_is_super,
								 ppp_superuser_bypass && caller_is_super);
	if (code != NULL)
		ppp_reject(username, code, &prof);

	/* step 7: a pre-hashed verifier is recorded as is */
	if (password_type != PASSWORD_TYPE_PLAINTEXT)
		verifier = pstrdup(shadow_pass);
	else
		verifier = encrypt_password(PASSWORD_TYPE_SCRAM_SHA_256, username,
									shadow_pass);

	/* step 8 */
	ppp_record_change(username, verifier);
	pfree(verifier);
}

static void
ppp_check_password_hook(const char *username, const char *shadow_pass,
						PasswordType password_type, Datum validuntil_time,
						bool validuntil_null)
{
	/* step 1 */
	if (ppp_enabled && !ppp_role_is_exempt(username))
	{
		MemoryContext cxt = CurrentMemoryContext;
		bool		save_in_hook = ppp_in_hook;
		bool		caller_is_super = superuser();
		Oid			save_userid;
		int			save_sec_context;
		pppSpiState st;

		GetUserIdAndSecContext(&save_userid, &save_sec_context);

		ppp_in_hook = true;
		PG_TRY();
		{
			/*
			 * step 2, without SPI: outside pg_pass_policy.database the
			 * policy never applies (PPP-003 or WARNING), even when the
			 * extension is installed there; PPP-004 if untrusted.
			 */
			bool		in_ppp_db = ppp_in_policy_database();

			if (!in_ppp_db)
				ppp_policy_not_applicable(username, false);
			else if (ppp_require_extension(false) == PPP_EXT_TRUSTED)
			{
				/*
				 * Read with the caller's identity: may the caller change the
				 * password of this existing role?  PostgreSQL checks it
				 * before calling the hook; this only makes sure that the
				 * history and min_age checks can never become an oracle
				 * should a caller of check_password_hook ever skip that
				 * check (SPEC 6.2, step 5).
				 */
				Oid			roleid = get_role_oid(username, true);
				bool		may_check_history =
					ppp_may_check_history(save_userid, caller_is_super, roleid);

				/* steps 3 to 8, in one elevated SPI session */
				ppp_spi_begin(&st);
				ppp_apply_policy(username, shadow_pass, password_type,
								 caller_is_super, roleid, may_check_history,
								 cxt);
				ppp_spi_end(&st);
			}
			else
				ppp_policy_not_applicable(username, true);
		}
		PG_CATCH();
		{
			/* GUC level and SPI connection are released by the abort */
			ppp_in_hook = save_in_hook;
			SetUserIdAndSecContext(save_userid, save_sec_context);
			ppp_rethrow_hidden(cxt);
		}
		PG_END_TRY();
		ppp_in_hook = save_in_hook;
	}

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

/*
 * Evaluate the password argument (#1) of check_password(); the copies of the
 * secret are wiped even if a check raises an ERROR.
 */
static const char *
ppp_check_secret(FunctionCallInfo fcinfo, const char *username, Oid roleid,
				 const pppProfile *prof, bool may_check_history)
{
	text	   *volatile pwtext = NULL;
	char	   *volatile password = NULL;
	const char *volatile code = NULL;

	PG_TRY();
	{
		pwtext = PG_GETARG_TEXT_PP(1);
		password = text_to_cstring(pwtext);

		/*
		 * superuser_bypass ignored, and min_age checked even for a
		 * superuser caller (caller_is_super = false): the answer is that
		 * of the profile of the role, not of the caller's own ALTER ROLE
		 */
		code = ppp_evaluate_password(username, roleid, password,
									 get_password_type(password), prof,
									 may_check_history, false, false);
	}
	PG_FINALLY();
	{
		if (password != NULL)
		{
			ppp_secure_zero(password, strlen(password));
			pfree(password);
		}
		/* wipe the detoasted copy, if any (never the caller's datum) */
		if (pwtext != NULL && (Pointer) pwtext != PG_GETARG_POINTER(1))
			ppp_secure_zero(VARDATA_ANY(pwtext), VARSIZE_ANY_EXHDR(pwtext));
	}
	PG_END_TRY();

	return code;
}

/*
 * pass_policy.check_password(role text, password text) RETURNS text (STRICT)
 *
 * NULL if the password complies with the effective profile of the role,
 * otherwise "PPP-0xx: reason".  No side effect, no audit.
 *
 * pg_pass_policy.superuser_bypass is ignored: the function answers for the
 * profile of the role, so that a superuser checking a password for someone
 * else (client, CLI) is not told that a weak password complies.  The hook
 * still lets such a password through for a superuser caller.  For the same
 * reason the minimum age (PPP-030) is checked whoever the caller, while the
 * hook does not apply it to a superuser caller.
 *
 * The minimum age, history and current password checks are only done when
 * the caller is a superuser, the role itself, or may change the role's
 * password (PPP_MAY_SET_PASSWORD_OF), or when the role does not exist yet:
 * the history is then checked by name, as CREATE ROLE ... PASSWORD would
 * do it (same predicate as the hook).  The function cannot be used as an
 * oracle on the passwords of an existing role the caller may not change, or
 * on the date of its last change.
 *
 * The whole body runs in one elevated SPI session whose GUC guard keeps
 * STATEMENT/CONTEXT (which hold the password) out of the messages emitted
 * meanwhile; an ERROR is re-thrown with both hidden (ppp_rethrow_hidden).
 */
Datum
ppp_check_password(PG_FUNCTION_ARGS)
{
	MemoryContext cxt = CurrentMemoryContext;
	char	   *username;
	bool		caller_is_super;
	Oid			caller;
	Oid			save_userid;
	int			save_sec_context;
	pppSpiState st;
	text	   *volatile result = NULL;

	/* identity of the caller, before the SPI session elevates it */
	caller_is_super = superuser();
	caller = GetUserId();
	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	username = text_to_cstring(PG_GETARG_TEXT_PP(0));

	PG_TRY();
	{
		const char *code;
		pppProfile	prof;
		Oid			roleid;
		bool		may_check_history;

		/* outside pg_pass_policy.database the hook never applies the policy */
		ppp_require_policy_database(true);
		/* catalog lookups only: checked before the elevation */
		(void) ppp_require_extension(true);
		ppp_spi_begin(&st);

		/* everything that can fail without needing the secret comes first */
		ppp_load_effective_profile(username, &prof, cxt);
		roleid = get_role_oid(username, true);
		/* same predicate as the hook (explicit user id, no elevation) */
		may_check_history = ppp_may_check_history(caller, caller_is_super,
												  roleid);

		code = ppp_check_secret(fcinfo, username, roleid, &prof,
								may_check_history);

		/* back to the caller's identity, GUC level and memory context */
		ppp_spi_end(&st);

		if (code != NULL)
		{
			char	   *msg;
			char	   *detail;
			char	   *hint;

			ppp_describe(code, &prof, &msg, &detail, &hint);
			result = cstring_to_text(detail ? psprintf("%s: %s. %s", code, msg, detail)
									 : psprintf("%s: %s", code, msg));
		}
	}
	PG_CATCH();
	{
		SetUserIdAndSecContext(save_userid, save_sec_context);
		ppp_rethrow_hidden(cxt);
	}
	PG_END_TRY();

	if (result == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(result);
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
 * Generator shared by generate_password() and _generate_password_for().
 *
 * Builds a password from pg_strong_random only, satisfying the class minima
 * of the given profile (or "default"), then shuffles it (Fisher-Yates).
 * Runs in one elevated SPI session (profile lookup), like check_password();
 * the work buffer is wiped on every path.
 *
 * rolename (NULL for generate_password()) is the role that will receive
 * the password: with reject_username in the profile, draws that contain
 * its name or its reverse (PPP-017, any case, names of 3 characters or
 * more) are drawn again, so that rotate_password() never fails at random
 * on its own hook for a short role name.
 */
static text *
ppp_generate(int32 length, const char *profname, const char *rolename)
{
	MemoryContext cxt = CurrentMemoryContext;
	Oid			save_userid;
	int			save_sec_context;
	pppSpiState st;
	char	   *volatile buf = NULL;
	text	   *volatile result = NULL;

	if (length < PPP_GEN_MIN_LENGTH || length > PPP_GEN_MAX_LENGTH)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("password length must be between %d and %d",
						PPP_GEN_MIN_LENGTH, PPP_GEN_MAX_LENGTH),
				 errhidestmt(true),
				 errhidecontext(true)));

	GetUserIdAndSecContext(&save_userid, &save_sec_context);

	PG_TRY();
	{
		pppProfile	prof;
		pppProfile	genprof;
		int			need_lower,
					need_upper,
					need_digit,
					need_special;
		int			nclasses_forced;
		int			tries;

		/* PPP-003 (enforce_database) or WARNING outside the policy database */
		ppp_require_policy_database(false);
		/* catalog lookups only: checked before the elevation */
		(void) ppp_require_extension(true);
		ppp_spi_begin(&st);
		ppp_load_named_profile(profname, &prof, cxt);

		if (length < prof.min_length ||
			(prof.max_length > 0 && length > prof.max_length))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password length %d does not comply with profile \"%s\"",
							length, prof.name),
					 errdetail("The profile requires between %d and %d characters.",
							   prof.min_length, prof.max_length)));

		/*
		 * Same computation as pass_policy._generator_minimum() (SQL
		 * script), used by the profile_classes_fit constraint and by
		 * _rotate_role(): keep both in step.
		 */
		need_lower = Max(prof.min_lower, 1);
		need_upper = Max(prof.min_upper, 1);
		need_digit = Max(prof.min_digit, 1);
		need_special = Max(prof.min_special, 0);

		/*
		 * Specials are only forced when the profile asks for them, or when
		 * the three other classes are not enough to reach min_classes.
		 */
		nclasses_forced = 3 + (need_special > 0);
		if (nclasses_forced < prof.min_classes)
			need_special = 1;

		if (need_lower + need_upper + need_digit + need_special > length)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password length %d is too small for the character class minima of profile \"%s\"",
							length, prof.name)));

		/*
		 * The generated password is re-validated without the dictionary,
		 * and with the role name only when the target role is known.
		 */
		genprof = prof;
		genprof.reject_username = prof.reject_username && rolename != NULL;
		genprof.reject_dictionary = false;

		buf = palloc(length + 1);
		for (tries = 0;; tries++)
		{
			const char *code;
			int			pos = 0;
			int			i;

			for (i = 0; i < need_lower; i++)
				buf[pos++] = ppp_random_char(ppp_alpha_lower);
			for (i = 0; i < need_upper; i++)
				buf[pos++] = ppp_random_char(ppp_alpha_upper);
			for (i = 0; i < need_digit; i++)
				buf[pos++] = ppp_random_char(ppp_alpha_digit);
			for (i = 0; i < need_special; i++)
				buf[pos++] = ppp_random_char(ppp_alpha_special);
			while (pos < length)
				buf[pos++] = ppp_random_char(ppp_alpha_all);
			buf[length] = '\0';

			/* Fisher-Yates shuffle */
			for (i = length - 1; i > 0; i--)
			{
				int			j = (int) ppp_random_uniform((uint32) i + 1);
				char		tmp = buf[i];

				buf[i] = buf[j];
				buf[j] = tmp;
			}

			if (ppp_validate(rolename ? rolename : "", buf, &genprof, &code))
				break;
			/*
			 * Length and class minima are checked above and the class
			 * composition is guaranteed by construction; the special
			 * alphabet has no space (PPP-020).  A draw containing the role
			 * name (PPP-017) is rare and drawn again.  The only rule random
			 * draws can keep breaking is max_repeat (PPP-019): a profile whose
			 * class minima force many characters from a small class (for
			 * instance min_digit close to the length) with a low max_repeat
			 * is practically infeasible.  That is a profile problem
			 * (22023); any other code would be a bug of the generator.
			 */
			if (tries >= PPP_GEN_MAX_TRIES)
			{
				if (strcmp(code, "PPP-019") == 0)
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("pg_pass_policy: could not generate a password compliant with profile \"%s\" (%s)",
									prof.name, code),
							 errdetail("After %d attempts, max_repeat = %d could still not be met with the character class minima of the profile.",
									   PPP_GEN_MAX_TRIES, prof.max_repeat),
							 errhint("Raise max_repeat, lower the class minima or use another length.")));
				ereport(ERROR,
						(errcode(ERRCODE_INTERNAL_ERROR),
						 errmsg("pg_pass_policy: could not generate a password compliant with profile \"%s\" (%s)",
								prof.name, code)));
			}
		}

		/* the result must survive SPI_finish() */
		{
			MemoryContext old = MemoryContextSwitchTo(cxt);

			result = cstring_to_text_with_len(buf, length);
			MemoryContextSwitchTo(old);
		}
		ppp_secure_zero(buf, length + 1);
		pfree(buf);
		buf = NULL;

		ppp_spi_end(&st);
	}
	PG_CATCH();
	{
		if (buf != NULL)
			ppp_secure_zero(buf, length + 1);
		SetUserIdAndSecContext(save_userid, save_sec_context);
		ppp_rethrow_hidden(cxt);
	}
	PG_END_TRY();

	return result;
}

/*
 * pass_policy.generate_password(length int DEFAULT 24, profile text
 * DEFAULT NULL) RETURNS text
 *
 * Not STRICT: length NULL = 24, profile NULL = "default".  The target role
 * is unknown: the role name rule (PPP-017) is not applied to the draws.
 */
Datum
ppp_generate_password(PG_FUNCTION_ARGS)
{
	int32		length = PG_ARGISNULL(0) ? 24 : PG_GETARG_INT32(0);
	char	   *profname = PG_ARGISNULL(1) ? "default" :
		text_to_cstring(PG_GETARG_TEXT_PP(1));

	PG_RETURN_TEXT_P(ppp_generate(length, profname, NULL));
}

/*
 * pass_policy._generate_password_for(role name, length int, profile text)
 * RETURNS text (addition to SPEC 4, internal, used by _rotate_role())
 *
 * Same as generate_password(), and the draws containing the role name or
 * its reverse are rejected (PPP-017).  Not STRICT: length NULL = 24,
 * profile NULL = "default"; role NULL = no role name rule.
 */
Datum
ppp_generate_password_for(PG_FUNCTION_ARGS)
{
	const char *rolename = PG_ARGISNULL(0) ? NULL :
		NameStr(*PG_GETARG_NAME(0));
	int32		length = PG_ARGISNULL(1) ? 24 : PG_GETARG_INT32(1);
	char	   *profname = PG_ARGISNULL(2) ? "default" :
		text_to_cstring(PG_GETARG_TEXT_PP(2));

	PG_RETURN_TEXT_P(ppp_generate(length, profname, rolename));
}

/*
 * pass_policy._in_password_hook() RETURNS bool
 *
 * True only while this backend is executing the pg_pass_policy
 * check_password_hook (addition to SPEC 4, used by the SQL guard of
 * record_password_change()).
 */
Datum
ppp_in_password_hook(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(ppp_in_hook);
}

/*
 * pass_policy._record_done(role name) RETURNS bool (STRICT)
 *
 * True if the password hook recorded a password change of this role in the
 * current transaction (record_password_change() returned).  Used by
 * _ensure_recorded() after an ALTER ROLE ... PASSWORD issued by the
 * extension itself, instead of guessing from role_state.
 */
Datum
ppp_record_done(PG_FUNCTION_ARGS)
{
	Name		role = PG_GETARG_NAME(0);

	PG_RETURN_BOOL(ppp_password_recorded(NameStr(*role)));
}
