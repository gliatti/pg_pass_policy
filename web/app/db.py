"""Database access: psycopg 3 pool and the queries used by the pages.

Rules (SPEC §8): every value is a bound parameter, every administrative
action goes through a pass_policy.* function (never ALTER ROLE directly),
and no password is ever logged or kept beyond the HTTP response.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any, TypeVar

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

STATUSES = ("ok", "warning", "grace", "expired", "locked", "never_expires", "unknown")
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


class InfinityTimestamptzLoader(TimestamptzLoader):
    """psycopg cannot represent 'infinity' (manual locks): load it as a string."""

    def load(self, data: Any) -> Any:  # type: ignore[override]
        raw = bytes(data)
        if raw in (b"infinity", b"-infinity"):
            return raw.decode()
        return super().load(data)


def _configure(conn: Connection) -> None:
    conn.adapters.register_loader("timestamptz", InfinityTimestamptzLoader)


def make_pool(settings: Settings) -> ConnectionPool:
    return ConnectionPool(
        settings.database_url,
        min_size=settings.pool_min,
        max_size=max(settings.pool_max, settings.pool_min),
        timeout=settings.pool_timeout,
        open=False,
        name="pgpp-web",
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
        yield conn


# the dependency to declare in the endpoints: `conn: Connection = db.CONN`
CONN: Any = Depends(get_conn, scope="function")

T = TypeVar("T")


class ExtensionNotPreloaded(Exception):
    """pg_pass_policy is not in shared_preload_libraries: every view and
    every function backed by the shared memory fails with SQLSTATE 55000.
    Raised by the first query of a request that hits it, shown as a
    dedicated page (main.py) with the server's HINT."""

    def __init__(self, message: str, hint: str | None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


def not_preloaded(exc: BaseException) -> ExtensionNotPreloaded | None:
    """The ExtensionNotPreloaded matching a 55000 error raised because the
    library is not preloaded (message or HINT naming shared_preload_libraries,
    or the shared memory reported as not initialized), None for anything else
    (another 55000, such as PPP-004 "schema is not trusted", included)."""
    if not isinstance(exc, psycopg.errors.ObjectNotInPrerequisiteState):
        return None
    message = error_message(exc)
    hint = exc.diag.message_hint
    text = f"{message} {hint or ''}"
    if "shared_preload_libraries" in text or "shared memory is not initialized" in text:
        return ExtensionNotPreloaded(message, hint)
    return None


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
_PPP_CODE = re.compile(r"PPP-\d{3}\b")


def is_extension_error(exc: psycopg.Error) -> bool:
    """Whether a PostgreSQL error is a refusal to show the user as is (see
    EXTENSION_SQLSTATES): a message of the extension ("pg_pass_policy: ...",
    "PPP-0xx: ..."), or one of its SQLSTATEs, or a data error caused by the
    submitted values."""
    if not_preloaded(exc) is not None:
        return False
    message = error_message(exc)
    if message.startswith("pg_pass_policy:") or _PPP_CODE.match(message):
        return True
    sqlstate = exc.sqlstate or ""
    return sqlstate in EXTENSION_SQLSTATES or sqlstate.startswith(USER_INPUT_SQLSTATE_CLASSES)


def run_action(
    conn: Connection, action: Callable[..., T], *args: Any
) -> tuple[T | None, str | None]:
    """Run one pass_policy action in a savepoint, then commit it: (result,
    None) on success, (None, error message) when the extension refuses it
    (is_extension_error(): the savepoint is rolled back, the connection
    stays usable for the response).  Any other PostgreSQL error propagates
    once the savepoint is rolled back: main.py logs it and shows the generic
    500 page (ExtensionNotPreloaded: the dedicated page).

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

    A 55000 (ObjectNotInPrerequisiteState) of another cause than a missing
    preload gives None: the dashboard shows "worker not running" instead of
    failing, the savepoint keeps the request transaction usable for the
    queries that follow.  The library not being preloaded (not_preloaded():
    "must be loaded via shared_preload_libraries", "shared memory is not
    initialized") propagates: the request gets the "extension not
    preloaded" page (main.py), including /maintenance, whose first query is
    this one.  Any other error (missing function, privilege, lost
    connection...) propagates too: the generic 500 page.
    """
    try:
        with conn.transaction():
            return conn.execute(WORKER_STATUS_SQL).fetchone()
    except psycopg.errors.ObjectNotInPrerequisiteState as exc:
        if not_preloaded(exc) is not None:
            raise
        log.warning("worker status unavailable: %s", error_message(exc))
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
        "SELECT role_name, profile, expires_at, grace_until, days_left, status"
        "  FROM pass_policy.v_expiring ORDER BY expires_at NULLS LAST, role_name LIMIT %s",
        (limit,),
    ).fetchall()


def get_role(conn: Connection, role: str) -> dict[str, Any] | None:
    return conn.execute(f"{_ROLE_SELECT} WHERE v.role_name = %s", (role,)).fetchone()


def rotate_password(conn: Connection, role: str, length: int = 24) -> str:
    """Returns the new password: shown once to the caller, never stored."""
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


def parse_since(text: str | None) -> datetime | str | None:
    """'2026-10-27' / '2026-10-27T10:00' -> datetime ; '7 days' -> interval text ; '' -> None."""
    if not text or not text.strip():
        return None
    text = text.strip()
    try:
        return datetime.fromisoformat(text)
    except ValueError:
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


def list_audit(
    conn: Connection,
    role: str | None = None,
    event_type: str | None = None,
    since: datetime | str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    where, params = _audit_where(role, event_type, since)
    # one scan: the total comes with each row (count(*) OVER () is computed
    # before LIMIT/OFFSET)
    rows = conn.execute(
        "SELECT id, event_time, event_type, role_name, actor, database, client_addr,"
        "       application_name, details, count(*) OVER () AS total"
        f"  FROM pass_policy.audit_log WHERE {where}"
        " ORDER BY id DESC LIMIT %s OFFSET %s",
        [*params, limit, offset],
    ).fetchall()
    if rows:
        total = rows[0]["total"]
        for row in rows:
            del row["total"]
    elif offset:
        # page past the end: no row carries the total, count separately
        total = conn.execute(
            f"SELECT count(*) AS n FROM pass_policy.audit_log WHERE {where}", params
        ).fetchone()["n"]
    else:
        total = 0
    return rows, total


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


def switch_pair(conn: Connection, pair: str, length: int = 24) -> dict[str, Any]:
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
