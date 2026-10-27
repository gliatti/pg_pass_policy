"""Profiles: list, create, edit, delete, assign / unassign."""

from __future__ import annotations

from typing import Any

import psycopg
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from psycopg import Connection

from app import db
from app.templating import render

router = APIRouter(prefix="/profiles")

LABELS = {
    "min_length": "Minimum length",
    "max_length": "Maximum length",
    "min_lower": "Minimum lower-case letters",
    "min_upper": "Minimum upper-case letters",
    "min_digit": "Minimum digits",
    "min_special": "Minimum special characters",
    "min_classes": "Distinct character classes required (0-4)",
    "reject_username": "Reject passwords containing the role name",
    "reject_dictionary": "Reject dictionary words",
    "reject_prehashed": "Reject pre-hashed (MD5/SCRAM) passwords",
    "max_repeat": "Maximum identical consecutive characters (0 = off)",
    "history_count": "Previous passwords compared (0 = off)",
    "history_days": "Maximum age of compared history entries (days)",
    "max_age": "Password lifetime (interval, empty = never expires)",
    "min_age": "Minimum time between two changes (interval)",
    "grace_period": "Grace period after expiry (interval)",
    "warn_before": "Warn before expiry (interval)",
    "max_failures": "Failed logins before lock (0 = off)",
    "failure_window": "Failure counting window (interval, 0 = none)",
    "lock_duration": "Automatic lock duration (interval, empty = manual unlock)",
}


def settings_from_form(form: Any) -> dict[str, Any]:
    """Type the form values into the jsonb expected by create/alter_profile()."""
    settings: dict[str, Any] = {}
    for key, kind in db.PROFILE_FIELDS:
        raw = form.get(key)
        value = raw.strip() if isinstance(raw, str) else ""
        if kind == "bool":
            settings[key] = raw is not None and value not in ("", "0", "false", "off")
        elif kind == "int":
            if value == "":
                raise ValueError(f"{LABELS[key]}: a value is required")
            try:
                settings[key] = int(value)
            except ValueError as exc:
                raise ValueError(f"{LABELS[key]}: not an integer") from exc
        elif kind == "interval":
            if value == "":
                raise ValueError(f"{LABELS[key]}: a value is required")
            settings[key] = value
        else:  # interval_null
            settings[key] = value or None
    return settings


def _page(request: Request, conn: Connection, **extra: Any) -> Response:
    profiles = db.list_profiles(conn)
    context = {
        "profiles": profiles,
        "assignments": db.assignments(conn),
        "login_roles": db.login_roles(conn),
        # same order as profile_names(): derived, no second query
        "profile_names": [p["name"] for p in profiles],
        **extra,
    }
    return render(request, "profiles/index.html", context)


def _assignments_fragment(
    request: Request, conn: Connection, error: str | None = None, notice: str | None = None
) -> Response:
    context = {
        "assignments": db.assignments(conn),
        "login_roles": db.login_roles(conn),
        "profile_names": db.profile_names(conn),
        "error": error,
        "notice": notice,
    }
    return render(request, "profiles/_assignments.html", context, 422 if error else 200)


@router.get("", name="profiles")
def profiles_page(request: Request, conn: Connection = Depends(db.get_conn)):
    return _page(request, conn)


@router.get("/new", name="profile_new")
def profile_new(request: Request, conn: Connection = Depends(db.get_conn)):
    defaults = db.get_profile(conn, "default") or {}
    return render(
        request,
        "profiles/form.html",
        {"profile": None, "values": defaults, "fields": db.PROFILE_FIELDS, "labels": LABELS},
    )


@router.post("", name="profile_create")
async def profile_create(request: Request, conn: Connection = Depends(db.get_conn)):
    form = await request.form()
    name = str(form.get("name", "")).strip()
    values = {k: form.get(k) for k, _ in db.PROFILE_FIELDS}
    values["name"] = name
    try:
        if not name:
            raise ValueError("a profile name is required")
        settings = settings_from_form(form)
        with conn.transaction():
            db.create_profile(conn, name, settings)
    except (ValueError, psycopg.Error) as exc:
        message = db.error_message(exc) if isinstance(exc, psycopg.Error) else str(exc)
        return render(
            request,
            "profiles/_form.html",
            {
                "profile": None,
                "values": values,
                "fields": db.PROFILE_FIELDS,
                "labels": LABELS,
                "error": message,
            },
            status_code=422,
        )
    target = request.url_for("profiles").path
    if request.headers.get("hx-request") == "true":
        return Response(status_code=204, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)


# same wording as pass_policy._require_target_allowed(): the dropdown already
# hides privileged roles, but the form value is user-controlled
_PRIVILEGED = 'only a superuser can manage privileged role "{}"'


# declared before the /{name} routes so that they are not captured by them
@router.post("/assign", name="profile_assign")
def profile_assign(
    request: Request,
    role: str = Form(max_length=128),
    profile: str = Form(max_length=128),
    conn: Connection = Depends(db.get_conn),
):
    role, profile = role.strip(), profile.strip()
    if db.privileged_target_refused(conn, role):
        return _assignments_fragment(request, conn, error=_PRIVILEGED.format(role))
    try:
        with conn.transaction():
            db.assign_profile(conn, role, profile)
    except psycopg.Error as exc:
        return _assignments_fragment(request, conn, error=db.error_message(exc))
    return _assignments_fragment(request, conn, notice=f"Profile {profile} assigned to {role}")


@router.post("/unassign", name="profile_unassign")
def profile_unassign(
    request: Request, role: str = Form(max_length=128), conn: Connection = Depends(db.get_conn)
):
    role = role.strip()
    if db.privileged_target_refused(conn, role):
        return _assignments_fragment(request, conn, error=_PRIVILEGED.format(role))
    try:
        with conn.transaction():
            db.unassign_profile(conn, role)
    except psycopg.Error as exc:
        return _assignments_fragment(request, conn, error=db.error_message(exc))
    return _assignments_fragment(request, conn, notice=f"{role} is back on the default profile")


@router.get("/{name}", name="profile_edit")
def profile_edit(request: Request, name: str, conn: Connection = Depends(db.get_conn)):
    profile = db.get_profile(conn, name)
    if profile is None:
        return render(
            request, "error.html", {"status_code": 404, "detail": "Profile not found"}, 404
        )
    return render(
        request,
        "profiles/form.html",
        {"profile": profile, "values": profile, "fields": db.PROFILE_FIELDS, "labels": LABELS},
    )


@router.post("/{name}", name="profile_update")
async def profile_update(request: Request, name: str, conn: Connection = Depends(db.get_conn)):
    form = await request.form()
    profile = db.get_profile(conn, name)
    if profile is None:
        return render(request, "_alert.html", {"error": "Profile not found"}, 404)
    values = {k: form.get(k) for k, _ in db.PROFILE_FIELDS}
    values["name"] = name
    error = notice = None
    try:
        settings = settings_from_form(form)
        with conn.transaction():
            db.alter_profile(conn, name, settings)
        notice = "Profile updated"
        values = db.get_profile(conn, name) or values
    except (ValueError, psycopg.Error) as exc:
        error = db.error_message(exc) if isinstance(exc, psycopg.Error) else str(exc)
    return render(
        request,
        "profiles/_form.html",
        {
            "profile": profile,
            "values": values,
            "fields": db.PROFILE_FIELDS,
            "labels": LABELS,
            "error": error,
            "notice": notice,
        },
        status_code=422 if error else 200,
    )


@router.post("/{name}/delete", name="profile_delete")
def profile_delete(request: Request, name: str, conn: Connection = Depends(db.get_conn)):
    try:
        with conn.transaction():
            db.drop_profile(conn, name)
    except psycopg.Error as exc:
        return render(request, "_alert.html", {"error": db.error_message(exc)}, 422)
    target = request.url_for("profiles").path
    if request.headers.get("hx-request") == "true":
        return Response(status_code=204, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)
