"""Maintenance: run pass_policy.run_maintenance() on demand."""

from __future__ import annotations

from fastapi import APIRouter, Request
from psycopg import Connection

from app import db
from app.logfilter import get_logger
from app.templating import alert_response, render, reread_warning

router = APIRouter(prefix="/maintenance")
log = get_logger("maintenance")

REREAD_WARNING = reread_warning("Maintenance completed", "the worker status")


@router.get("", name="maintenance")
def maintenance_page(request: Request, conn: Connection = db.CONN):
    return render(request, "maintenance/index.html", {"worker": db.worker_status(conn)})


@router.post("/run", name="maintenance_run")
def maintenance_run(request: Request, conn: Connection = db.CONN):
    actions, error = db.run_action(conn, db.run_maintenance)
    if error is not None:
        return alert_response(request, error)
    # the maintenance is committed: a failing read of the worker status (lost
    # connection, privilege revoked) must not turn its result into a 500
    # page, which would hide the actions taken and invite a second run
    worker, warning = db.reread_after_commit(
        conn, db.worker_status, log, "maintenance run", REREAD_WARNING
    )
    return render(
        request,
        "maintenance/_result.html",
        {"actions": actions, "worker": worker, "warning": warning},
    )
