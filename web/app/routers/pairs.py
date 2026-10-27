"""Rotation pairs: list, create, switch (password shown once)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Form, Request
from psycopg import Connection

from app import db
from app.logfilter import get_logger
from app.templating import reread_warning, reveal_response

router = APIRouter(prefix="/pairs")
log = get_logger("pairs")

REREAD_WARNING = reread_warning("The pair was switched", "the pair list")
NO_ROW_WARNING = (
    "Pair {}: the switch was applied but returned no row, so its new password"
    " cannot be shown; the pair list below shows its current state."
)


def _content(
    request: Request,
    conn: Connection,
    template: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    warning: str | None = None,
    switched: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
) -> Any:
    unavailable = False
    if switched is None:
        pairs = db.list_pairs(conn)
    else:
        # the switch is committed: whatever happens to the re-read, this
        # response is the only place the new password will ever be shown
        read, warning = db.reread_after_commit(
            conn, db.list_pairs, log, f"pair {switched['pair']} switched", REREAD_WARNING
        )
        unavailable = read is None
        pairs = read or []
    context = {
        "pairs": pairs,
        "pairs_unavailable": unavailable,
        "warning": warning,
        "notice": notice,
        "switched": switched,
        "form": form or {},
    }
    password = switched["password"] if switched else None
    return reveal_response(request, template, context, password=password, error=error)


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
    if result is None:
        # committed, but switch_rotation_pair() returned no row: no password
        # to show, said as such (200: the action did happen, it must not be
        # retried blindly) rather than a TypeError (500) after the commit;
        # no password to protect, so the list is read the normal way
        log.error("pair %s: switch applied but no row returned", pair)
        return _content(request, conn, "pairs/_content.html", warning=NO_ROW_WARNING.format(pair))
    # the password is in this response only (no-store); never logged nor stored
    return _content(request, conn, "pairs/_content.html", switched={"pair": pair, **result})
