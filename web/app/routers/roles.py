"""Roles: filterable table and lock/unlock/expire/rotate actions (HTMX)."""

from __future__ import annotations

import secrets
from typing import Any

import psycopg
from fastapi import APIRouter, Depends, Form, Query, Request
from psycopg import Connection

from app import db
from app.logfilter import get_logger
from app.templating import NO_STORE, render

router = APIRouter(prefix="/roles")
log = get_logger("roles")

REREAD_WARNING = (
    "The password was changed, but the role could not be read back: reload the page"
    " to see its current state."
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
    rows = db.list_roles(
        conn, status=filters["status"], profile=filters["profile"], search=filters["q"]
    )
    return {
        "roles": rows,
        "truncated": len(rows) >= db.MAX_ROLES,
        "filters": filters,
        "statuses": db.STATUSES,
        "profiles": db.profile_names(conn),
    }


@router.get("", name="roles")
def roles_page(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = Depends(db.get_conn),
):
    return render(request, "roles/index.html", _table_context(conn, filters))


@router.get("/table", name="roles_table")
def roles_table(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = Depends(db.get_conn),
):
    return render(request, "roles/_table.html", _table_context(conn, filters))


def _row_response(
    request: Request,
    conn: Connection,
    role: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    password: str | None = None,
) -> Any:
    reread_failed = False
    if password is None:
        row = db.get_role(conn, role)
    else:
        # the rotation is committed: whatever happens to the re-read, this
        # response is the only place the new password will ever be shown
        try:
            with conn.transaction():
                row = db.get_role(conn, role)
        except psycopg.Error as exc:
            log.error("role %s rotated, its row could not be re-read: %s", role, exc)
            row, reread_failed = None, True
    context = {
        "r": row,
        "role_name": role,
        "error": error,
        "notice": notice,
        "warning": REREAD_WARNING if reread_failed else None,
        "reread_failed": reread_failed,
        "password": password,
        "uid": secrets.token_hex(4),
    }
    headers = NO_STORE if password else None
    status_code = 200 if error is None else 422
    return render(request, "roles/_row.html", context, status_code=status_code, headers=headers)


# {role:path}: a role name may contain '/' (sent percent-encoded, decoded by
# the server); every action route ends with its own suffix, so a role named
# "x/lock" cannot be mistaken for the lock action on "x"


def _run(conn: Connection, action, *args: Any) -> str | None:
    """Run one action in a savepoint; return the error message, if any."""
    try:
        with conn.transaction():
            action(conn, *args)
    except psycopg.Error as exc:
        return db.error_message(exc)
    _commit(conn)
    return None


def _commit(conn: Connection) -> None:
    """Commit before re-reading the row: the extension applies its
    shared-memory changes (lock, unlock, failure counter) at commit, so
    v_role_status read in the same transaction would still show the old
    state."""
    conn.commit()


@router.post("/{role:path}/rotate", name="role_rotate")
def rotate(
    request: Request,
    role: str,
    length: int = Form(default=24, ge=8, le=128),
    conn: Connection = Depends(db.get_conn),
):
    password: str | None = None
    try:
        with conn.transaction():
            password = db.rotate_password(conn, role, length)
    except psycopg.Error as exc:
        return _row_response(request, conn, role, error=db.error_message(exc))
    _commit(conn)
    # the password exists only in this response (no-store), never in a log or a URL
    return _row_response(request, conn, role, password=password)


@router.post("/{role:path}/lock", name="role_lock")
def lock(
    request: Request,
    role: str,
    duration: str = Form(default="", max_length=64),
    reason: str = Form(default="", max_length=500),
    conn: Connection = Depends(db.get_conn),
):
    error = _run(conn, db.lock_role, role, duration.strip(), reason.strip())
    notice = None if error else ("Role locked" + (" until unlock" if not duration.strip() else ""))
    return _row_response(request, conn, role, error=error, notice=notice)


@router.post("/{role:path}/unlock", name="role_unlock")
def unlock(request: Request, role: str, conn: Connection = Depends(db.get_conn)):
    error = _run(conn, db.unlock_role, role)
    return _row_response(
        request, conn, role, error=error, notice=None if error else "Role unlocked"
    )


@router.post("/{role:path}/expire", name="role_expire")
def expire(request: Request, role: str, conn: Connection = Depends(db.get_conn)):
    error = _run(conn, db.expire_password, role)
    return _row_response(
        request, conn, role, error=error, notice=None if error else "Password expired"
    )
