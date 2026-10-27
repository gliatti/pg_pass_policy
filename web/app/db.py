"""Database access: psycopg 3 pool and the queries used by the pages.

Rules (SPEC §8): every value is a bound parameter, every administrative
action goes through a pass_policy.* function (never ALTER ROLE directly),
and no password is ever logged or kept beyond the HTTP response.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any

import psycopg
from fastapi import Request
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.datetime import TimestamptzLoader
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.config import Settings

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


def set_actor(conn: Connection, settings: Settings, user: str | None) -> None:
    """Record the web user in application_name (copied into audit_log by the extension)."""
    name = f"{settings.app_name}:{user or 'anonymous'}"[:63]
    conn.execute("SELECT set_config('application_name', %s, false)", (name,))


def get_conn(request: Request) -> Iterator[Connection]:
    """FastAPI dependency: one pooled connection per request, committed on success."""
    pool: ConnectionPool = request.app.state.pool
    with pool.connection() as conn:
        set_actor(conn, request.app.state.settings, getattr(request.state, "user", None))
        yield conn


def error_message(exc: psycopg.Error) -> str:
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


def worker_status(conn: Connection) -> dict[str, Any] | None:
    return conn.execute(
        "SELECT pid, last_run, last_reload, tracked_roles FROM pass_policy.worker_status()"
    ).fetchone()


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
    "  LEFT JOIN pass_policy.role_state s ON s.role_name = v.role_name"
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


def _session_is_superuser(conn: Connection) -> bool:
    return conn.execute(
        "SELECT coalesce((SELECT s.rolsuper FROM pg_catalog.pg_roles s"
        "                  WHERE s.rolname = session_user), false) AS su"
    ).fetchone()["su"]


def login_roles(conn: Connection) -> list[str]:
    """Login roles the service role may act on: privileged roles (SUPERUSER,
    REPLICATION, BYPASSRLS) are listed only when the session is a superuser,
    mirroring pass_policy._require_target_allowed()."""
    return [
        r["rolname"]
        for r in conn.execute(
            "SELECT rolname FROM pg_catalog.pg_roles"
            " WHERE rolcanlogin"
            "   AND (NOT (rolsuper OR rolreplication OR rolbypassrls) OR %s)"
            " ORDER BY rolname",
            (_session_is_superuser(conn),),
        )
    ]


def privileged_target_refused(conn: Connection, role: str) -> bool:
    """True when `role` is privileged and the session is not a superuser: the
    web application then refuses the action itself, whatever the extension
    does (defense in depth, same rule as _require_target_allowed())."""
    row = conn.execute(
        "SELECT (rolsuper OR rolreplication OR rolbypassrls) AS privileged"
        "  FROM pg_catalog.pg_roles WHERE rolname = %s",
        (role,),
    ).fetchone()
    if row is None or not row["privileged"]:
        return False
    return not _session_is_superuser(conn)


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


def assignments(conn: Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT rp.role_name, p.name AS profile, rp.assigned_at, rp.assigned_by"
        "  FROM pass_policy.role_profile rp"
        "  JOIN pass_policy.profile p ON p.profile_id = rp.profile_id"
        " ORDER BY rp.role_name"
    ).fetchall()


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
    total = conn.execute(
        f"SELECT count(*) AS n FROM pass_policy.audit_log WHERE {where}", params
    ).fetchone()["n"]
    rows = conn.execute(
        "SELECT id, event_time, event_type, role_name, actor, database, client_addr,"
        "       application_name, details"
        f"  FROM pass_policy.audit_log WHERE {where}"
        " ORDER BY id DESC LIMIT %s OFFSET %s",
        [*params, limit, offset],
    ).fetchall()
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
