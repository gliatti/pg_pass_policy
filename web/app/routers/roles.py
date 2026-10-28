"""Roles: filterable table and lock/unlock/expire/rotate actions (HTMX)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Query, Request
from psycopg import Connection

from app import db
from app.logfilter import get_logger
from app.templating import render, reread_warning, reveal_response

router = APIRouter(prefix="/roles")
log = get_logger("roles")

REREAD_WARNING = reread_warning("The password was changed", "the role")
NO_PASSWORD_WARNING = (
    "Role {}: the rotation was applied but returned no password, so the new password"
    " cannot be shown; rotate again to get one."
)


def _filters(
    status: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=128),
) -> dict[str, Any]:
    return {
        "status": status if status in db.STATUSES else None,
        "profile": profile or None,
        "q": (q or "").strip() or None,
    }


def _table_context(conn: Connection, filters: dict[str, Any]) -> dict[str, Any]:
    # one row more than shown: tells "exactly MAX_ROLES" from "more"
    rows = db.list_roles(
        conn,
        status=filters["status"],
        profile=filters["profile"],
        search=filters["q"],
        limit=db.MAX_ROLES + 1,
    )
    return {
        "roles": rows[: db.MAX_ROLES],
        "truncated": len(rows) > db.MAX_ROLES,
        "filters": filters,
        "statuses": db.STATUSES,
    }


@router.get("", name="roles")
def roles_page(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = db.CONN,
):
    # the profile filter belongs to the page, not to the table fragment that
    # roles_table() returns on every refresh
    context = {**_table_context(conn, filters), "profiles": db.profile_names(conn)}
    return render(request, "roles/index.html", context)


@router.get("/table", name="roles_table")
def roles_table(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = db.CONN,
):
    return render(request, "roles/_table.html", _table_context(conn, filters))


def _row_response(
    request: Request,
    conn: Connection,
    role: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    warning: str | None = None,
    password: str | None = None,
) -> Any:
    if password is None:
        row = db.get_role(conn, role)
    else:
        # the rotation is committed: whatever happens to the re-read, this
        # response is the only place the new password will ever be shown
        row, warning = db.reread_after_commit(
            conn, lambda c: db.get_role(c, role), log, f"role {role} rotated", REREAD_WARNING
        )
    context = {
        "r": row,
        "role_name": role,
        "notice": notice,
        "warning": warning,
        "password": password,
    }
    return reveal_response(request, "roles/_row.html", context, password=password, error=error)


# {role:path}: a role name may contain '/' (sent percent-encoded, decoded by
# the server); every action route ends with its own suffix, so a role named
# "x/lock" cannot be mistaken for the lock action on "x"


@router.post("/{role:path}/rotate", name="role_rotate")
def rotate(
    request: Request,
    role: str,
    length: int | None = Form(default=None, ge=8, le=128),
    conn: Connection = db.CONN,
):
    password, error = db.run_action(conn, db.rotate_password, role, length)
    if error is not None:
        return _row_response(request, conn, role, error=error)
    if not password:
        # committed, but rotate_password() returned NULL or an empty string:
        # said as such (200: the rotation did happen, the role's old password
        # no longer works) rather than a password displayed as "None" or an
        # empty reveal box, as for a pair switch (pairs.NO_ROW_WARNING); no
        # password to protect, so the row is read the normal way
        log.error("role %s: rotation applied but no password returned", role)
        return _row_response(request, conn, role, warning=NO_PASSWORD_WARNING.format(role))
    # the password exists only in this response (no-store), never in a log or a URL
    return _row_response(request, conn, role, password=password)


@router.post("/{role:path}/lock", name="role_lock")
def lock(
    request: Request,
    role: str,
    duration: str = Form(default="", max_length=64),
    reason: str = Form(default="", max_length=500),
    conn: Connection = db.CONN,
):
    _, error = db.run_action(conn, db.lock_role, role, duration.strip(), reason.strip())
    notice = None if error else ("Role locked" + (" until unlock" if not duration.strip() else ""))
    return _row_response(request, conn, role, error=error, notice=notice)


@router.post("/{role:path}/unlock", name="role_unlock")
def unlock(request: Request, role: str, conn: Connection = db.CONN):
    _, error = db.run_action(conn, db.unlock_role, role)
    return _row_response(
        request, conn, role, error=error, notice=None if error else "Role unlocked"
    )


@router.post("/{role:path}/expire", name="role_expire")
def expire(request: Request, role: str, conn: Connection = db.CONN):
    _, error = db.run_action(conn, db.expire_password, role)
    return _row_response(
        request, conn, role, error=error, notice=None if error else "Password expired"
    )
