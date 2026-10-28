"""Audit log: filters (role, type, since) and pagination."""

from __future__ import annotations

import math
from typing import Any

import psycopg
from fastapi import APIRouter, Depends, Query, Request
from psycopg import Connection

from app import db
from app.templating import render

router = APIRouter(prefix="/audit")


def _filters(
    role: str | None = Query(default=None, max_length=128),
    type: str | None = Query(default=None, max_length=64),
    since: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1, le=100000),
) -> dict[str, Any]:
    return {
        "role": (role or "").strip() or None,
        "type": type if type in db.EVENT_TYPES else None,
        "since": (since or "").strip() or None,
        "page": page,
    }


def _page_count(total: int, page_size: int) -> int:
    return max(1, math.ceil(total / page_size))


def total_label(result: db.AuditPage) -> str:
    """The total shown above the table: exact, or "10,000+" when capped."""
    if result.capped:
        return f"{db.AUDIT_COUNT_CAP:,}+"
    return str(result.total)


def _context(request: Request, conn: Connection, filters: dict[str, Any]) -> dict[str, Any]:
    page_size = request.app.state.settings.page_size
    error = None
    result = db.AuditPage([], 0)
    page = filters["page"]
    past_end = False
    try:
        with conn.transaction():
            since = db.parse_since(filters["since"])

            def fetch(number: int) -> db.AuditPage:
                return db.list_audit(
                    conn,
                    role=filters["role"],
                    event_type=filters["type"],
                    since=since,
                    limit=page_size,
                    offset=(number - 1) * page_size,
                )

            result = fetch(page)
            # a page past the end (stale link, hand-typed URL).  Total not
            # capped: it is exact, the real last page is shown (not an empty
            # table with a "page 7 / 2" footer); no second query when
            # nothing matches (the last page is empty as well).  Total
            # capped: the last page is unknown (only "more than 10,000"),
            # the requested page is shown empty with a link to the first
            # page, never a page presented as the last one.
            if not result.rows and page > 1:
                if result.capped:
                    past_end = True
                else:
                    page = min(page, _page_count(result.total, page_size))
                    if result.total:
                        result = fetch(page)
    except (psycopg.DataError, db.InvalidFilter) as exc:
        error = f"Invalid filter: {db.error_message(exc)}"
    # more than AUDIT_COUNT_CAP events: the page count is unknown, the
    # pager relies on has_next
    pages = None if result.capped else _page_count(result.total, page_size)
    if pages is not None:
        page = min(page, pages)
    return {
        "events": result.rows,
        "total": result.total,
        "total_label": total_label(result),
        "has_next": result.has_next,
        "past_end": past_end,
        "page": page,
        "pages": pages,
        "filters": filters,
        "event_types": db.EVENT_TYPES,
        "error": error,
    }


@router.get("", name="audit")
def audit_page(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = db.CONN,
):
    return render(request, "audit/index.html", _context(request, conn, filters))


@router.get("/table", name="audit_table")
def audit_table(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    conn: Connection = db.CONN,
):
    return render(request, "audit/_table.html", _context(request, conn, filters))
