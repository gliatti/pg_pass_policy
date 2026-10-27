"""Rotation pairs: list, create, switch (password shown once)."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Form, Request
from psycopg import Connection

from app import db
from app.logfilter import get_logger
from app.templating import NO_STORE, render

router = APIRouter(prefix="/pairs")
log = get_logger("pairs")

REREAD_WARNING = (
    "The pair was switched, but the pair list could not be read back: reload the page"
    " to see the current state."
)


def _content(
    request: Request,
    conn: Connection,
    template: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    switched: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
) -> Any:
    warning = None
    if switched is None:
        pairs = db.list_pairs(conn)
    else:
        # the switch is committed: whatever happens to the re-read, this
        # response is the only place the new password will ever be shown
        read, warning = db.reread_after_commit(
            conn, db.list_pairs, log, f"pair {switched['pair']} switched", REREAD_WARNING
        )
        pairs = read or []
    context = {
        "pairs": pairs,
        "warning": warning,
        "error": error,
        "notice": notice,
        "switched": switched,
        "form": form or {},
        "uid": secrets.token_hex(4),
    }
    return render(
        request,
        template,
        context,
        status_code=422 if error else 200,
        headers=NO_STORE if switched else None,
    )


@router.get("", name="pairs")
def pairs_page(request: Request, conn: Connection = db.CONN):
    return _content(request, conn, "pairs/index.html")


@router.post("", name="pair_create")
def pair_create(
    request: Request,
    pair_name: str = Form(max_length=128),
    role_a: str = Form(max_length=128),
    role_b: str = Form(max_length=128),
    group_role: str = Form(max_length=128),
    conn: Connection = db.CONN,
):
    values = {
        "pair_name": pair_name.strip(),
        "role_a": role_a.strip(),
        "role_b": role_b.strip(),
        "group_role": group_role.strip(),
    }
    error = None if all(values.values()) else "every field is required"
    if error is None:
        _, error = db.run_action(conn, lambda c: db.create_pair(c, **values))
    if error is not None:
        return _content(request, conn, "pairs/_content.html", error=error, form=values)
    return _content(
        request, conn, "pairs/_content.html", notice=f"Rotation pair {values['pair_name']} created"
    )


# {pair:path}: a pair name is free text and may contain '/'
@router.post("/{pair:path}/switch", name="pair_switch")
def pair_switch(
    request: Request,
    pair: str,
    length: int = Form(default=24, ge=8, le=128),
    conn: Connection = db.CONN,
):
    # run_action() commits before anything is shown: a password is displayed
    # only once it is durable (the request's own commit would come later)
    result, error = db.run_action(conn, db.switch_pair, pair, length)
    if error is not None:
        return _content(request, conn, "pairs/_content.html", error=error)
    # the password is in this response only (no-store); never logged nor stored
    return _content(request, conn, "pairs/_content.html", switched={"pair": pair, **result})
