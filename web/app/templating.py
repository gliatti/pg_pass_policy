"""Jinja2 environment, filters and per-request context."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse, Response

from app.csrf import get_csrf_token
from app.db import INFINITY
from app.security import route_path

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# htmx hardening: no eval, no <script> from responses, same-origin requests
# only, no history snapshot (a revealed password must never reach
# localStorage), indicator CSS comes from app.css (no injected <style>).
HTMX_CONFIG: dict[str, Any] = {
    "allowEval": False,
    "allowScriptTags": False,
    "selfRequestsOnly": True,
    "includeIndicatorStyles": False,
    "historyCacheSize": 0,
    "refreshOnHistoryMiss": True,
    "responseHandling": [
        {"code": "204", "swap": False},
        {"code": "[23]..", "swap": True},
        {"code": "[45]..", "swap": True, "error": True},
        {"code": "...", "swap": False},
    ],
}


def _static_versions(directory: Path) -> dict[str, str]:
    """A short hash of each static file's content, computed once at startup:
    appended to its URL (?v=...), it changes with the file, so that the
    browser's cache (max-age, see security.py) never serves an old copy
    after an upgrade."""
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


STATIC_VERSIONS = _static_versions(STATIC_DIR)


def is_hx(request: Request) -> bool:
    """The request was sent by htmx (HX-Request header)."""
    return request.headers.get("hx-request") == "true"


def fmt_ts(value: Any) -> str:
    """A timestamp to the minute, with its UTC offset ("2026-10-28 14:05+01:00"):
    psycopg returns timestamptz values in the TimeZone of the session, which
    is the server's unless set otherwise, not necessarily the reader's."""
    if value is None:
        return "—"
    if isinstance(value, str):
        return "∞ (manual)" if value == INFINITY else value
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="minutes")
    return str(value)


def fmt_interval(value: Any) -> str:
    if value is None:
        return "—"
    return str(value)


def fmt_json(value: Any) -> str:
    if value is None or value == {}:
        return ""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _context(request: Request) -> dict[str, Any]:
    def path_for(route: str, /, **params: Any) -> str:
        # path only (keeps root_path): scheme and host must not be guessed
        # behind a reverse proxy.  Parameters are percent-encoded: a role
        # name may contain '/', '?', '#' or '%' (the routes taking a role or
        # a pair use the path convertor, the server decodes the path)
        quoted = {k: quote(str(v), safe="") for k, v in params.items()}
        return request.url_for(route, **quoted).path

    def static_url(path: str) -> str:
        """The URL of a static file, with its content version (?v=)."""
        url = path_for("static", path=path)
        version = STATIC_VERSIONS.get(path)
        return f"{url}?v={version}" if version else url

    user = getattr(request.state, "user", None)
    return {
        "path_for": path_for,
        "static_url": static_url,
        # path without the root_path prefix (active navigation link)
        "route_path": route_path(request.scope),
        # no token (and no session cookie) for the anonymous error pages shown
        # before authentication: a token is only issued to an identified user
        "csrf_token": get_csrf_token(request) if user else "",
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        "user": user,
        "htmx_config": HTMX_CONFIG,
        "is_hx": is_hx(request),
    }


templates = Jinja2Templates(directory=str(TEMPLATES_DIR), context_processors=[_context])
templates.env.filters["ts"] = fmt_ts
templates.env.filters["interval"] = fmt_interval
templates.env.filters["jsonc"] = fmt_json


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    return templates.TemplateResponse(
        request, name, context or {}, status_code=status_code, headers=headers
    )


NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def redirect_to(request: Request, route: str) -> Response:
    """After a successful POST: HX-Redirect (204) for htmx, 303 otherwise."""
    target = request.url_for(route).path
    if is_hx(request):
        return Response(status_code=204, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)


def reread_warning(done: str, subject: str) -> str:
    """The warning shown with a one-time password when the state could not be
    re-read after the committed action (db.reread_after_commit())."""
    return f"{done}, but {subject} could not be read back: reload the page to see it."


def reveal_response(
    request: Request,
    template: str,
    context: dict[str, Any],
    *,
    password: str | None = None,
    error: str | None = None,
) -> Response:
    """A fragment that may carry a one-time password (_reveal.html): a fresh
    uid for its element ids, no-store when it carries a password, 422 when
    the action was refused.  The password is in this response only, never in
    a log, a URL or the session."""
    context = {**context, "error": error, "uid": secrets.token_hex(4)}
    return render(
        request,
        template,
        context,
        status_code=422 if error else 200,
        headers=NO_STORE if password else None,
    )
