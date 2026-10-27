"""Profiles: list, create, edit, delete, assign / unassign."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from psycopg import Connection
from starlette.datastructures import FormData

from app import db
from app.templating import redirect_to, render

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


# names that the profile routes cannot reach: /profiles/new, /profiles/assign
# and /profiles/unassign are fixed routes, "." and ".." are removed from the
# URL by the browser (dot segments).  The extension accepts them (its CHECK
# is ^[A-Za-z0-9_.-]{1,63}$): the web interface refuses to create or update
# them, such a profile is managed with SQL.
RESERVED_NAMES = frozenset({"new", "assign", "unassign", ".", ".."})
RESERVED_MESSAGE = (
    'the profile name "{}" is reserved by the web interface'
    " (new, assign, unassign, . and ..): choose another name or use SQL"
)


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


async def _read_form(request: Request) -> FormData:
    """The posted form, read by an async dependency so that the endpoints
    using it stay synchronous: FastAPI runs a `def` endpoint in its thread
    pool, where the blocking psycopg calls do not stall the event loop."""
    return await request.form()


FORM: Any = Depends(_read_form)


def _assignment_context(
    request: Request, conn: Connection, profile_names: list[str] | None = None
) -> dict[str, Any]:
    """The context of the assignments block, shared by the full page and the
    fragment returned by assign / unassign."""
    return {
        "assignments": db.assignments(conn),
        "login_roles": db.login_roles(conn, db.session_is_superuser(request, conn)),
        "profile_names": db.profile_names(conn) if profile_names is None else profile_names,
    }


def _page(request: Request, conn: Connection) -> Response:
    profiles = db.list_profiles(conn)
    # same order as profile_names(): derived, no second query
    context = _assignment_context(request, conn, [p["name"] for p in profiles])
    return render(request, "profiles/index.html", {"profiles": profiles, **context})


def _assignments_fragment(
    request: Request, conn: Connection, error: str | None = None, notice: str | None = None
) -> Response:
    context = {**_assignment_context(request, conn), "error": error, "notice": notice}
    return render(request, "profiles/_assignments.html", context, 422 if error else 200)


def _form_response(
    request: Request,
    profile: dict[str, Any] | None,
    values: Any,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    """The form fragment for htmx, the full page for a plain form post."""
    template = (
        "profiles/_form.html"
        if request.headers.get("hx-request") == "true"
        else "profiles/form.html"
    )
    context = {
        "profile": profile,
        "values": values,
        "fields": db.PROFILE_FIELDS,
        "labels": LABELS,
        "error": error,
        "notice": notice,
    }
    return render(request, template, context, status_code=422 if error else 200)


@router.get("", name="profiles")
def profiles_page(request: Request, conn: Connection = db.CONN):
    return _page(request, conn)


@router.get("/new", name="profile_new")
def profile_new(request: Request, conn: Connection = db.CONN):
    # the settings of the default profile as a starting point, but not its
    # name: the new profile must be named by the user
    defaults = {**(db.get_profile(conn, "default") or {}), "name": ""}
    return render(
        request,
        "profiles/form.html",
        {"profile": None, "values": defaults, "fields": db.PROFILE_FIELDS, "labels": LABELS},
    )


@router.post("", name="profile_create")
def profile_create(request: Request, form: FormData = FORM, conn: Connection = db.CONN):
    name = str(form.get("name", "")).strip()
    values = {k: form.get(k) for k, _ in db.PROFILE_FIELDS}
    values["name"] = name
    try:
        if not name:
            raise ValueError("a profile name is required")
        if name in RESERVED_NAMES:
            raise ValueError(RESERVED_MESSAGE.format(name))
        settings = settings_from_form(form)
    except ValueError as exc:
        return _form_response(request, None, values, error=str(exc))
    _, error = db.run_action(conn, db.create_profile, name, settings)
    if error is not None:
        return _form_response(request, None, values, error=error)
    return redirect_to(request, "profiles")


# declared before the /{name} routes so that they are not captured by them
@router.post("/assign", name="profile_assign")
def profile_assign(
    request: Request,
    role: str = Form(max_length=128),
    profile: str = Form(max_length=128),
    conn: Connection = db.CONN,
):
    role, profile = role.strip(), profile.strip()
    # a forged privileged target is refused by the extension itself
    # (_require_target_allowed()), its message is shown as is
    _, error = db.run_action(conn, db.assign_profile, role, profile)
    if error is not None:
        return _assignments_fragment(request, conn, error=error)
    return _assignments_fragment(request, conn, notice=f"Profile {profile} assigned to {role}")


@router.post("/unassign", name="profile_unassign")
def profile_unassign(
    request: Request, role: str = Form(max_length=128), conn: Connection = db.CONN
):
    role = role.strip()
    _, error = db.run_action(conn, db.unassign_profile, role)
    if error is not None:
        return _assignments_fragment(request, conn, error=error)
    return _assignments_fragment(request, conn, notice=f"{role} is back on the default profile")


# {name} (not {name:path}): the CHECK constraint of pass_policy.profile
# (name ~ '^[A-Za-z0-9_.-]{1,63}$') forbids '/', so a decoded profile name never
# spans two segments and "x/delete" cannot be mistaken for the delete action
# on "x" (tests/test_integration.py checks that such a name is refused)
@router.get("/{name}", name="profile_edit")
def profile_edit(request: Request, name: str, conn: Connection = db.CONN):
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
def profile_update(request: Request, name: str, form: FormData = FORM, conn: Connection = db.CONN):
    profile = db.get_profile(conn, name)
    if profile is None:
        # the generic error response: a page, or for htmx an alert retargeted
        # to #alerts (the form stays in place)
        raise HTTPException(status_code=404, detail="Profile not found")
    values = {k: form.get(k) for k, _ in db.PROFILE_FIELDS}
    values["name"] = name
    notice = None
    try:
        if name in RESERVED_NAMES:
            raise ValueError(RESERVED_MESSAGE.format(name))
        settings = settings_from_form(form)
    except ValueError as exc:
        return _form_response(request, profile, values, error=str(exc))
    _, error = db.run_action(conn, db.alter_profile, name, settings)
    if error is None:
        notice = "Profile updated"
        values = db.get_profile(conn, name) or values
    return _form_response(request, profile, values, error=error, notice=notice)


@router.post("/{name}/delete", name="profile_delete")
def profile_delete(request: Request, name: str, conn: Connection = db.CONN):
    _, error = db.run_action(conn, db.drop_profile, name)
    if error is not None:
        return render(request, "_alert.html", {"error": error}, 422)
    return redirect_to(request, "profiles")
