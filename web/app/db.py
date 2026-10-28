"""Database access: psycopg 3 pool and the queries used by the pages.

Rules (SPEC §8): every value is a bound parameter, every administrative
action goes through a pass_policy.* function (never ALTER ROLE directly),
and no password is ever logged or kept beyond the HTTP response.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, TypeVar

import psycopg
from fastapi import Depends, Request
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.datetime import TimestamptzLoader
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.config import Settings
from app.logfilter import get_logger

log = get_logger("db")

STATUSES = (
    "ok",
    "warning",
    "grace",
    "expired",
    "locked",
    "exempt",
    "never_expires",
    "unknown",
)
EVENT_TYPES = (
    "password_changed",
    "password_rejected",
    "auth_failed",
    "role_locked",
    "role_unlocked",
    "expiry_warning",
    "password_expired",
    "password_rotated",
    "profile_assigned",
    "profile_changed",
    "pair_switched",
    "valid_until_synced",
    "maintenance",
)
# profile settings accepted by create_profile()/alter_profile(): (key, kind)
PROFILE_FIELDS: tuple[tuple[str, str], ...] = (
    ("min_length", "int"),
    ("max_length", "int"),
    ("min_lower", "int"),
    ("min_upper", "int"),
    ("min_digit", "int"),
    ("min_special", "int"),
    ("min_classes", "int"),
    ("reject_username", "bool"),
    ("reject_dictionary", "bool"),
    ("reject_prehashed", "bool"),
    ("max_repeat", "int"),
    ("history_count", "int"),
    ("history_days", "int"),
    ("max_age", "interval_null"),
    ("min_age", "interval"),
    ("grace_period", "interval"),
    ("warn_before", "interval"),
    ("max_failures", "int"),
    ("failure_window", "interval"),
    ("lock_duration", "interval_null"),
)
MAX_ROLES = 500
INFINITY = "infinity"
NEG_INFINITY = "-infinity"
# the raw values compared by the loader, encoded once
_INFINITY_RAW = frozenset({INFINITY.encode(), NEG_INFINITY.encode()})


class InfinityTimestamptzLoader(TimestamptzLoader):
    """psycopg cannot represent 'infinity' (manual locks): load it as a string."""

    def load(self, data: Any) -> Any:  # type: ignore[override]
        raw = bytes(data)
        if raw in _INFINITY_RAW:
            return raw.decode()
        return super().load(data)


def _configure(conn: Connection) -> None:
    conn.adapters.register_loader("timestamptz", InfinityTimestamptzLoader)


def make_pool(settings: Settings) -> ConnectionPool:
    return ConnectionPool(
        settings.database_url,
        min_size=settings.pool_min,
        # config.Settings guarantees pool_max >= pool_min >= 0, pool_max >= 1
        max_size=settings.pool_max,
        timeout=settings.pool_timeout,
        open=False,
        name="pgpp-web",
        # a connection closed by the server (restart, idle timeout, network
        # cut) is detected and replaced when it leaves the pool, instead of
        # failing the request that gets it
        check=ConnectionPool.check_connection,
        kwargs={"row_factory": dict_row, "application_name": settings.app_name},
        configure=_configure,
    )


# application_name is limited to NAMEDATALEN - 1 = 63 bytes and the server
# replaces every non-ASCII byte of it with '?': the web user name is
# percent-encoded (ASCII only, "Émilie" -> "%C3%89milie", '%' itself encoded)
# and the whole value is cut at 63 bytes, never inside an escape sequence
APPLICATION_NAME_MAX = 63
_ACTOR_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:@+=,;!~*'()[]{}/ "
)


def application_name(prefix: str, user: str | None) -> str:
    """The application_name of a request: "<prefix>:<user>", ASCII only,
    at most 63 bytes (the user part is shortened first, by whole escapes)."""
    parts = [
        ch if ch in _ACTOR_SAFE else "".join(f"%{b:02X}" for b in ch.encode())
        for ch in (user or "anonymous")
    ]
    name = prefix.encode("ascii", "replace").decode() + ":"
    for part in parts:
        if len(name) + len(part) > APPLICATION_NAME_MAX:
            break
        name += part
    return name[:APPLICATION_NAME_MAX]


def set_actor(conn: Connection, settings: Settings, user: str | None) -> None:
    """Record the web user in application_name (copied into audit_log by the extension)."""
    name = application_name(settings.app_name, user)
    conn.execute("SELECT set_config('application_name', %s, false)", (name,))


def get_conn(request: Request) -> Iterator[Connection]:
    """FastAPI dependency: one pooled connection per request, committed on success.

    Always used through CONN (scope="function"): since FastAPI 0.118 a yield
    dependency of the default "request" scope is closed after the response
    is sent, so the implicit commit would come after a 303 / HX-Redirect
    (the next GET could miss the change, a failed commit would go unseen).
    With scope="function" the commit runs when the endpoint returns, before
    the response starts; a commit error becomes the usual 500 page.
    """
    pool: ConnectionPool = request.app.state.pool
    with pool.connection() as conn:
        set_actor(conn, request.app.state.settings, getattr(request.state, "user", None))
        try:
            yield conn
        except psycopg.Error as exc:
            # a pass_policy.* relation missing: the extension may not be
            # installed in this database (missing_extension_error())
            missing = missing_extension_error(conn, exc)
            if missing is None:
                raise
            raise missing from exc


# the dependency to declare in the endpoints: `conn: Connection = db.CONN`
CONN: Any = Depends(get_conn, scope="function")

T = TypeVar("T")


@dataclass(frozen=True)
class ExtensionUnavailable:
    """Why pg_pass_policy cannot serve a request, as found by
    extension_unavailable() (a value, never raised):

    - "not_preloaded": the library is not in shared_preload_libraries, every
      view and every function backed by the shared memory fails (55000);
    - "not_installed": the extension is not installed in the database the
      back-office connects to (schema pass_policy missing).

    main.py shows it as a dedicated page (503) with the server's message and
    HINT."""

    reason: Literal["not_preloaded", "not_installed"]
    message: str
    hint: str | None


NOT_INSTALLED_MESSAGE = "pg_pass_policy is not installed in this database"


def extension_unavailable(exc: BaseException) -> ExtensionUnavailable | None:
    """The ExtensionUnavailable matching an error raised because:

    - the library is not preloaded: a 55000 whose message or HINT names
      shared_preload_libraries, or reports the shared memory as not
      initialized;
    - the extension is not installed in the database: a 3F000
      (InvalidSchemaName, 'schema "pass_policy" does not exist', the error
      of any pass_policy.* function call without the extension), or the
      55000 "pg_pass_policy is not installed in this database" (raised by
      the server itself, and by get_conn() for a 42P01 once it has checked
      that the extension is absent, see missing_extension_error()).

    The 3F000 is recognised by its SQLSTATE alone, never by its text: the
    server translates its messages (lc_messages), 'le schéma « pass_policy »
    n'existe pas' in French.  Every query of the back-office names the
    pass_policy schema or pg_catalog only, so a missing schema is the
    extension's.

    None for anything else: another 55000 (PPP-004 "schema is not trusted"
    included), a 42P01 alone (the extension may be installed and out of
    step with the back-office: get_conn() decides)."""
    if isinstance(exc, psycopg.errors.InvalidSchemaName):
        return ExtensionUnavailable("not_installed", error_message(exc), exc.diag.message_hint)
    if not isinstance(exc, psycopg.errors.ObjectNotInPrerequisiteState):
        return None
    message = error_message(exc)
    hint = exc.diag.message_hint
    text = f"{message} {hint or ''}"
    if "shared_preload_libraries" in text or "shared memory is not initialized" in text:
        return ExtensionUnavailable("not_preloaded", message, hint)
    if message.startswith(NOT_INSTALLED_MESSAGE):
        return ExtensionUnavailable("not_installed", message, hint)
    return None


def missing_extension_error(conn: Connection, exc: BaseException) -> psycopg.Error | None:
    """For an error that may come from a missing extension (42P01), the
    55000 "not installed in this database" to raise instead when the
    extension is indeed absent from the database, None otherwise (another
    error, the extension installed: a back-office out of step with it, the
    generic 500 page; the check itself failing).

    The first query of most pages reads a view (pass_policy.v_role_status):
    without the extension it fails with 42P01, which a missing view of an
    installed extension would raise too, hence the check of pg_extension.
    The SQLSTATE alone selects the error, never its text (translated by the
    server with lc_messages): the check of pg_extension decides.  The failed
    transaction is rolled back first (the request is over)."""
    if not isinstance(exc, psycopg.errors.UndefinedTable):
        return None
    try:
        conn.rollback()
        row = conn.execute(
            "SELECT count(*) AS n FROM pg_catalog.pg_extension WHERE extname = 'pg_pass_policy'"
        ).fetchone()
    except psycopg.Error as check:
        log.error("could not check whether pg_pass_policy is installed: %s", check)
        return None
    if row is None or row["n"]:
        return None
    return psycopg.errors.ObjectNotInPrerequisiteState(NOT_INSTALLED_MESSAGE)


# SQLSTATEs shown in the action fragments (422): the ones the extension
# raises on a refused action (RAISE ... USING ERRCODE, ereport() in the C
# code) and the errors caused by the submitted values themselves (class 22:
# an interval that does not parse, an out-of-range integer; class 23: a CHECK
# constraint of pass_policy.profile).  Anything else (undefined table or
# function, lost connection, internal error...) is logged and gives the
# generic 500 page.
EXTENSION_SQLSTATES = frozenset(
    {
        "42501",  # insufficient_privilege (_require_admin, privileged target)
        "42704",  # undefined_object (role, profile, pair does not exist)
        "42710",  # duplicate_object (profile, pair already exists)
        "55006",  # object_in_use (profile assigned, default profile)
        "53400",  # configuration_limit_exceeded (shared memory full on lock)
        "28P01",  # invalid_password (PPP-0xx policy refusal)
        "P0001",  # raise_exception (plain RAISE EXCEPTION)
    }
)
USER_INPUT_SQLSTATE_CLASSES = ("22", "23")
# classes of internal errors (XX000 elog(ERROR), XX001 data corrupted...;
# 42703 undefined_column, 42883 undefined_function: an extension and a
# back-office out of step): never a refusal, even with a message of the
# extension, except the 42xxx of EXTENSION_SQLSTATES
INTERNAL_SQLSTATE_CLASSES = ("XX", "42")
_PPP_CODE = re.compile(r"PPP-\d{3}\b")


def is_extension_error(exc: psycopg.Error) -> bool:
    """Whether a PostgreSQL error is a refusal to show the user as is: one
    of EXTENSION_SQLSTATES, a data error caused by the submitted values
    (classes 22, 23), or a message of the extension ("pg_pass_policy: ...",
    "PPP-0xx: ...") with any other SQLSTATE but an internal one (classes XX
    and 42, see INTERNAL_SQLSTATE_CLASSES): "pg_pass_policy: unexpected
    extension state" (XX000) is a bug, not a refusal, and goes to the
    generic 500 page (logged once, by main.py, with its SQLSTATE).

    A 55000 (object_not_in_prerequisite_state) is never a refusal, whatever
    its message: library not preloaded, extension not installed, PPP-004
    "schema is not trusted"... are states of the server to fix, shown as
    the dedicated 503 page or the generic 500 page."""
    sqlstate = exc.sqlstate or ""
    if sqlstate == "55000" or extension_unavailable(exc) is not None:
        return False
    if sqlstate in EXTENSION_SQLSTATES or sqlstate.startswith(USER_INPUT_SQLSTATE_CLASSES):
        return True
    message = error_message(exc)
    if not (message.startswith("pg_pass_policy:") or _PPP_CODE.match(message)):
        return False
    return not sqlstate.startswith(INTERNAL_SQLSTATE_CLASSES)


def run_action(
    conn: Connection, action: Callable[..., T], *args: Any
) -> tuple[T | None, str | None]:
    """Run one pass_policy action in a savepoint, then commit it: (result,
    None) on success, (None, error message) when the extension refuses it
    (is_extension_error(): the savepoint is rolled back, the connection
    stays usable for the response).  Any other PostgreSQL error propagates
    once the savepoint is rolled back: main.py logs it and shows the generic
    500 page, or the dedicated 503 page when extension_unavailable() finds
    the extension not preloaded or not installed.

    The commit comes before anything is re-read or shown: the extension
    applies its shared-memory changes (lock, unlock, failure counter) at
    commit, so a view read in the same transaction would still show the old
    state, and a one-time password is displayed only once it is durable.  A
    failing commit propagates (the generic 500 page)."""
    try:
        with conn.transaction():
            result = action(conn, *args)
    except psycopg.Error as exc:
        if not is_extension_error(exc):
            raise
        return None, error_message(exc)
    conn.commit()
    return result, None


def reread_after_commit(
    conn: Connection,
    read: Callable[[Connection], T],
    logger: logging.Logger,
    what: str,
    warning: str,
) -> tuple[T | None, str | None]:
    """Re-read after a committed action whose result (a one-time password)
    must be shown whatever happens: (result, None), or, when the read
    fails, (None, warning) after logging the error instead of raising.  The
    read runs in a savepoint so that the connection stays usable."""
    try:
        with conn.transaction():
            return read(conn), None
    except psycopg.Error as exc:
        logger.error("%s, the re-read failed: %s", what, exc)
        return None, warning


def error_message(exc: Exception) -> str:
    """The message shown to the user: the primary message (and detail) of a
    PostgreSQL error, the text of any other exception (a form ValueError)."""
    if not isinstance(exc, psycopg.Error):
        return str(exc)
    diag = getattr(exc, "diag", None)
    if diag is not None and diag.message_primary:
        msg = diag.message_primary
        if diag.message_detail:
            msg += f" ({diag.message_detail})"
        return msg
    return str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__


# --- dashboard ---------------------------------------------------------------


def status_counts(conn: Connection) -> dict[str, int]:
    counts = dict.fromkeys(STATUSES, 0)
    for row in conn.execute(
        "SELECT status, count(*) AS n FROM pass_policy.v_role_status GROUP BY status"
    ):
        counts[row["status"]] = row["n"]
    return counts


WORKER_STATUS_SQL = (
    "SELECT pid, last_run, last_reload, tracked_roles FROM pass_policy.worker_status()"
)


def worker_status(conn: Connection) -> dict[str, Any] | None:
    """The worker state, or None when it cannot be read.

    None, with a warning in the log, for:

    - a 55000 (ObjectNotInPrerequisiteState) of another cause than an
      unavailable extension: the dashboard shows "worker not running";
    - a missing privilege (42501, InsufficientPrivilege: EXECUTE revoked on
      worker_status()) or a missing function (42883, UndefinedFunction: an
      older extension): the dashboard stays readable with partial rights.

    The savepoint keeps the request transaction usable for the queries that
    follow.  An unavailable extension (extension_unavailable(): library not
    preloaded, extension not installed) propagates: the request gets the
    dedicated page (main.py), including /maintenance, whose first query is
    this one.  Any other error (lost connection, undefined table...)
    propagates too: the generic 500 page.
    """
    try:
        with conn.transaction():
            return conn.execute(WORKER_STATUS_SQL).fetchone()
    except psycopg.errors.ObjectNotInPrerequisiteState as exc:
        if extension_unavailable(exc) is not None:
            raise
        log.warning("worker status unavailable: %s", error_message(exc))
        return None
    except (psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedFunction) as exc:
        log.warning("worker status unavailable (SQLSTATE %s): %s", exc.sqlstate, error_message(exc))
        return None


def recent_audit(conn: Connection, limit: int = 20) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT id, event_time, event_type, role_name, actor, database, client_addr,"
        "       application_name, details"
        "  FROM pass_policy.v_recent_audit LIMIT %s",
        (limit,),
    ).fetchall()


# --- roles -------------------------------------------------------------------

_ROLE_SELECT = (
    "SELECT v.role_name, v.profile, v.password_changed_at, v.expires_at, v.grace_until,"
    "       v.days_left, v.locked_until, v.failed_count, v.status,"
    # is_exempt / expiry_state: the expiry of the password alone, that
    # status hides behind 'locked' or 'exempt'
    "       v.is_exempt, v.expiry_state,"
    "       s.locked_by, s.lock_reason, s.must_change"
    "  FROM pass_policy.v_role_status v"
    # by OID: role_state.role_name keeps the former name after ALTER ROLE
    # ... RENAME until run_maintenance() or the next lock_role()
    "  LEFT JOIN pass_policy.role_state s ON s.role_oid = v.role_oid"
)


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_roles(
    conn: Connection,
    status: str | None = None,
    profile: str | None = None,
    search: str | None = None,
    limit: int = MAX_ROLES,
) -> list[dict[str, Any]]:
    where = ["true"]
    params: list[Any] = []
    if status:
        where.append("v.status = %s")
        params.append(status)
    if profile:
        where.append("v.profile = %s")
        params.append(profile)
    if search:
        where.append("v.role_name ILIKE %s")
        params.append(_like(search))
    params.append(limit)
    return conn.execute(
        f"{_ROLE_SELECT} WHERE {' AND '.join(where)} ORDER BY v.role_name LIMIT %s", params
    ).fetchall()


def expiring_roles(conn: Connection, limit: int = 50) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT role_name, profile, expires_at, grace_until, days_left, status, expiry_state"
        "  FROM pass_policy.v_expiring ORDER BY expires_at NULLS LAST, role_name LIMIT %s",
        (limit,),
    ).fetchall()


def get_role(conn: Connection, role: str) -> dict[str, Any] | None:
    return conn.execute(f"{_ROLE_SELECT} WHERE v.role_name = %s", (role,)).fetchone()


def rotate_password(conn: Connection, role: str, length: int | None = None) -> str:
    """Returns the new password: shown once to the caller, never stored.

    A NULL length lets the extension pick 24 characters raised to the
    profile's min_length (and capped by its max_length)."""
    row = conn.execute(
        "SELECT pass_policy.rotate_password(%s, %s) AS password", (role, length)
    ).fetchone()
    return row["password"]


def lock_role(conn: Connection, role: str, duration: str | None, reason: str | None) -> None:
    conn.execute(
        "SELECT pass_policy.lock_role(%s, %s::interval, %s)",
        (role, duration or None, reason or None),
    )


def unlock_role(conn: Connection, role: str) -> None:
    conn.execute("SELECT pass_policy.unlock_role(%s)", (role,))


def expire_password(conn: Connection, role: str) -> None:
    conn.execute("SELECT pass_policy.expire_password(%s)", (role,))


def _query_session_is_superuser(conn: Connection) -> bool:
    return conn.execute(
        "SELECT coalesce((SELECT s.rolsuper FROM pg_catalog.pg_roles s"
        "                  WHERE s.rolname = session_user), false) AS su"
    ).fetchone()["su"]


def session_is_superuser(request: Request, conn: Connection) -> bool:
    """Whether the service role is a superuser: queried once, on first use,
    then kept in app.state (every pooled connection uses the same role; a
    change of its attributes needs a restart of the application)."""
    state = request.app.state
    cached = getattr(state, "session_superuser", None)
    if cached is None:
        cached = state.session_superuser = _query_session_is_superuser(conn)
    return cached


# Display filter of the profile assignment form only: the privileged roles
# are not offered when the service role is not a superuser.  Forged values
# need no check here: every pass_policy.* function that takes a target role
# (assign_profile() and unassign_profile() included) refuses a privileged one
# through pass_policy._require_target_allowed(), and that error is shown.
# The filter applies the extension's own predicate, pass_policy._is_privileged()
# (executable by pass_policy_admin), as _require_target_allowed() does: to the
# role itself and to every role it belongs to, even indirectly.  The privileged
# roles are computed once (one _is_privileged() call per role, a STABLE SQL
# function), then each login role is checked against that short list (pg_*
# roles and the few roles with an attribute) instead of against every role.
LOGIN_ROLES_SQL = (
    "WITH privileged AS MATERIALIZED ("
    "  SELECT p.oid FROM pg_catalog.pg_roles p WHERE pass_policy._is_privileged(p.oid))"
    " SELECT r.rolname FROM pg_catalog.pg_roles r"
    "  WHERE r.rolcanlogin"
    "    AND (%s OR NOT EXISTS (SELECT FROM privileged x"
    "                            WHERE x.oid = r.oid"
    "                               OR pg_catalog.pg_has_role(r.oid, x.oid, 'MEMBER')))"
    "  ORDER BY r.rolname"
)


def login_roles(conn: Connection, superuser: bool) -> list[str]:
    """Login roles offered in the assignment form: the privileged ones
    (see LOGIN_ROLES_SQL) only when the service role is a superuser."""
    return [r["rolname"] for r in conn.execute(LOGIN_ROLES_SQL, (superuser,))]


# --- profiles ----------------------------------------------------------------

_PROFILE_SELECT = (
    "SELECT p.profile_id, p.name, p.min_length, p.max_length, p.min_lower, p.min_upper,"
    "       p.min_digit, p.min_special, p.min_classes, p.reject_username, p.reject_dictionary,"
    "       p.reject_prehashed, p.max_repeat, p.history_count, p.history_days,"
    "       p.max_age::text AS max_age, p.min_age::text AS min_age,"
    "       p.grace_period::text AS grace_period, p.warn_before::text AS warn_before,"
    "       p.max_failures, p.failure_window::text AS failure_window,"
    "       p.lock_duration::text AS lock_duration, p.created_at, p.updated_at,"
    "       (SELECT count(*) FROM pass_policy.role_profile rp"
    "         WHERE rp.profile_id = p.profile_id) AS assigned_roles"
    "  FROM pass_policy.profile p"
)


def list_profiles(conn: Connection) -> list[dict[str, Any]]:
    return conn.execute(f"{_PROFILE_SELECT} ORDER BY (p.name <> 'default'), p.name").fetchall()


def get_profile(conn: Connection, name: str) -> dict[str, Any] | None:
    return conn.execute(f"{_PROFILE_SELECT} WHERE p.name = %s", (name,)).fetchone()


def profile_names(conn: Connection) -> list[str]:
    return [
        r["name"]
        for r in conn.execute(
            "SELECT name FROM pass_policy.profile ORDER BY (name <> 'default'), name"
        )
    ]


_ASSIGNMENTS_SQL = (
    # the current name, by OID: role_profile.role_name keeps the former name
    # after ALTER ROLE ... RENAME (until run_maintenance() or the next
    # assignment); a dropped role (row left for the purge) keeps its stored
    # name, which unassign_profile() matches
    "SELECT coalesce(r.rolname::text, rp.role_name) AS role_name, p.name AS profile,"
    "       rp.assigned_at, rp.assigned_by"
    "  FROM pass_policy.role_profile rp"
    "  JOIN pass_policy.profile p ON p.profile_id = rp.profile_id"
    "  LEFT JOIN pg_catalog.pg_roles r ON r.oid = rp.role_oid"
    " ORDER BY 1"
)


def assignments(conn: Connection) -> list[dict[str, Any]]:
    return conn.execute(_ASSIGNMENTS_SQL).fetchall()


def create_profile(conn: Connection, name: str, settings: dict[str, Any]) -> int:
    row = conn.execute(
        "SELECT pass_policy.create_profile(%s, %s) AS id", (name, Jsonb(settings))
    ).fetchone()
    return row["id"]


def alter_profile(conn: Connection, name: str, settings: dict[str, Any]) -> None:
    conn.execute("SELECT pass_policy.alter_profile(%s, %s)", (name, Jsonb(settings)))


def drop_profile(conn: Connection, name: str) -> None:
    conn.execute("SELECT pass_policy.drop_profile(%s)", (name,))


def assign_profile(conn: Connection, role: str, profile: str) -> None:
    conn.execute("SELECT pass_policy.assign_profile(%s, %s)", (role, profile))


def unassign_profile(conn: Connection, role: str) -> None:
    conn.execute("SELECT pass_policy.unassign_profile(%s)", (role,))


# --- audit -------------------------------------------------------------------


class InvalidFilter(ValueError):
    """A filter value refused before any query (shown as "Invalid filter")."""


# starts like an ISO date (2026-10-27, 2026-1-5, 2026-10-27T10:00...): parsed
# as a date or refused, never handed to PostgreSQL as an interval
_DATE_LIKE_RE = re.compile(r"^\d{4}-\d")
# a number without unit ('7', '-3', '1.5'): PostgreSQL would read it as
# seconds, rarely what was meant
_BARE_NUMBER_RE = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)$")


def parse_since(text: str | None) -> datetime | str | None:
    """'2026-10-27' / '2026-10-27T10:00' -> datetime ; '7 days' -> interval text ; '' -> None.

    InvalidFilter for a value that looks like a date but is not one
    ('2026-13-45': "invalid date") and for a bare number ('7': a unit is
    required).  Any other text is an interval checked by PostgreSQL (a
    DataError for an invalid one)."""
    if not text or not text.strip():
        return None
    text = text.strip()
    if _BARE_NUMBER_RE.match(text):
        raise InvalidFilter(
            f"since {text!r}: a number needs a unit ('7 days', '12 hours') or use a date"
            " (YYYY-MM-DD)"
        )
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        if _DATE_LIKE_RE.match(text):
            raise InvalidFilter(
                f"since {text!r}: invalid date (expected YYYY-MM-DD or YYYY-MM-DDTHH:MM)"
            ) from None
        return text


def _audit_where(
    role: str | None, event_type: str | None, since: datetime | str | None
) -> tuple[str, list[Any]]:
    where = ["true"]
    params: list[Any] = []
    if role:
        where.append("role_name = %s")
        params.append(role)
    if event_type:
        where.append("event_type = %s")
        params.append(event_type)
    if isinstance(since, datetime):
        where.append("event_time >= %s")
        params.append(since)
    elif since:
        where.append("event_time >= now() - %s::interval")
        params.append(since)
    return " AND ".join(where), params


# the total shown above the audit table is exact up to this number of
# matching events, "10,000+" beyond (see list_audit())
AUDIT_COUNT_CAP = 10_000


@dataclass(frozen=True)
class AuditPage:
    """A page of the audit log.

    total is exact unless capped, in which case more than AUDIT_COUNT_CAP
    events match (total is then AUDIT_COUNT_CAP + 1).  has_next: another
    page follows this one."""

    rows: list[dict[str, Any]]
    total: int
    capped: bool = False
    has_next: bool = False


def list_audit(
    conn: Connection,
    role: str | None = None,
    event_type: str | None = None,
    since: datetime | str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> AuditPage:
    """One page of events, newest first, and how many events match.

    The page is read with one row more than shown (LIMIT limit + 1), which
    tells whether a next page exists without counting.  The total then
    costs:

    - nothing on the last page (offset + rows shown) or when nothing
      matches at all;
    - a bounded count otherwise (a next page exists): it stops after
      AUDIT_COUNT_CAP + 1 rows, so that a large audit_log is never scanned
      whole to display "10,000+";
    - an exact count only for a page past the end (stale link, hand-typed
      URL), so that the caller can show the real last page.

    count(*) OVER () would instead compute the whole match before LIMIT, on
    every page."""
    where, params = _audit_where(role, event_type, since)
    rows = conn.execute(
        "SELECT id, event_time, event_type, role_name, actor, database, client_addr,"
        "       application_name, details"
        f"  FROM pass_policy.audit_log WHERE {where}"
        " ORDER BY id DESC LIMIT %s OFFSET %s",
        [*params, limit + 1, offset],
    ).fetchall()
    has_next = len(rows) > limit
    del rows[limit:]
    if rows and not has_next:
        return AuditPage(rows, offset + len(rows))
    if not rows and not offset:
        return AuditPage(rows, 0)
    if rows:
        n = conn.execute(
            f"SELECT count(*) AS n FROM (SELECT 1 FROM pass_policy.audit_log WHERE {where}"
            " LIMIT %s) AS matching",
            [*params, AUDIT_COUNT_CAP + 1],
        ).fetchone()["n"]
        return AuditPage(rows, n, capped=n > AUDIT_COUNT_CAP, has_next=True)
    n = conn.execute(
        f"SELECT count(*) AS n FROM pass_policy.audit_log WHERE {where}", params
    ).fetchone()["n"]
    return AuditPage(rows, n)


# --- rotation pairs ----------------------------------------------------------


def list_pairs(conn: Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT pair_name, role_a, role_b, group_role, active_role, previous_role,"
        "       switched_at, previous_valid_until"
        "  FROM pass_policy.rotation_pair ORDER BY pair_name"
    ).fetchall()


def create_pair(
    conn: Connection, pair_name: str, role_a: str, role_b: str, group_role: str
) -> None:
    conn.execute(
        "SELECT pass_policy.create_rotation_pair(%s, %s, %s, %s)",
        (pair_name, role_a, role_b, group_role),
    )


def switch_pair(conn: Connection, pair: str, length: int | None = None) -> dict[str, Any]:
    """Returns active_role, password (shown once), previous_role, previous_valid_until."""
    return conn.execute(
        "SELECT active_role, password, previous_role, previous_valid_until"
        "  FROM pass_policy.switch_rotation_pair(%s, %s)",
        (pair, length),
    ).fetchone()


# --- maintenance -------------------------------------------------------------


def run_maintenance(conn: Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT action, role_name, details FROM pass_policy.run_maintenance()"
    ).fetchall()
