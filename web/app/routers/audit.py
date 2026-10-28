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


def _context(request: Request, conn: Connection, filters: dict[str, Any]) -> dict[str, Any]:
    page_size = request.app.state.settings.page_size
    error = None
    rows: list[dict[str, Any]] = []
    total = 0
    page = filters["page"]
    try:
        with conn.transaction():
            since = db.parse_since(filters["since"])

            def fetch(number: int) -> tuple[list[dict[str, Any]], int]:
                return db.list_audit(
                    conn,
                    role=filters["role"],
                    event_type=filters["type"],
                    since=since,
                    limit=page_size,
                    offset=(number - 1) * page_size,
                )

            rows, total = fetch(page)
            # a page past the end (stale link, hand-typed URL): the last
            # page, not an empty table with a "page 7 / 2" footer; no second
            # query when nothing matches (the last page is empty as well)
            clamped = min(page, _page_count(total, page_size))
            if clamped != page:
                page = clamped
                if total:
                    rows, total = fetch(page)
    except psycopg.DataError as exc:
        error = f"Invalid filter: {db.error_message(exc)}"
    pages = _page_count(total, page_size)
    page = min(page, pages)
    return {
        "events": rows,
        "total": total,
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
