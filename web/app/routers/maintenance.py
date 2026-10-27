"""Maintenance: run pass_policy.run_maintenance() on demand."""

from __future__ import annotations

import psycopg
from fastapi import APIRouter, Depends, Request
from psycopg import Connection

from app import db
from app.templating import render

router = APIRouter(prefix="/maintenance")


@router.get("", name="maintenance")
def maintenance_page(request: Request, conn: Connection = Depends(db.get_conn)):
    return render(request, "maintenance/index.html", {"worker": db.worker_status(conn)})


@router.post("/run", name="maintenance_run")
def maintenance_run(request: Request, conn: Connection = Depends(db.get_conn)):
    try:
        with conn.transaction():
            actions = db.run_maintenance(conn)
    except psycopg.Error as exc:
        return render(request, "_alert.html", {"error": db.error_message(exc)}, 422)
    return render(
        request,
        "maintenance/_result.html",
        {"actions": actions, "worker": db.worker_status(conn)},
    )
