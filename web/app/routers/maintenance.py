"""Maintenance: run pass_policy.run_maintenance() on demand."""

from __future__ import annotations

from fastapi import APIRouter, Request
from psycopg import Connection

from app import db
from app.templating import alert_response, render

router = APIRouter(prefix="/maintenance")


@router.get("", name="maintenance")
def maintenance_page(request: Request, conn: Connection = db.CONN):
    return render(request, "maintenance/index.html", {"worker": db.worker_status(conn)})


@router.post("/run", name="maintenance_run")
def maintenance_run(request: Request, conn: Connection = db.CONN):
    actions, error = db.run_action(conn, db.run_maintenance)
    if error is not None:
        return alert_response(request, error)
    return render(
        request,
        "maintenance/_result.html",
        {"actions": actions, "worker": db.worker_status(conn)},
    )
