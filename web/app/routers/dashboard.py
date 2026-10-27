"""Dashboard: counters per status, worker status, last audit events."""

from __future__ import annotations

from fastapi import APIRouter, Request
from psycopg import Connection

from app import db
from app.templating import render

router = APIRouter()


@router.get("/", name="dashboard")
def dashboard(request: Request, conn: Connection = db.CONN):
    counts = db.status_counts(conn)
    return render(
        request,
        "dashboard.html",
        {
            "counts": counts,
            "total": sum(counts.values()),
            "worker": db.worker_status(conn),
            "events": db.recent_audit(conn, 20),
            "expiring": db.expiring_roles(conn),
        },
    )
