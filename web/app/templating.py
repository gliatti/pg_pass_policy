"""Jinja2 environment, filters and per-request context."""

from __future__ import annotations

import json
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


def fmt_ts(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        return "∞ (manual)" if value == INFINITY else value
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
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

    user = getattr(request.state, "user", None)
    return {
        "path_for": path_for,
        # path without the root_path prefix (active navigation link)
        "route_path": route_path(request.scope),
        # no token (and no session cookie) for the anonymous error pages shown
        # before authentication: a token is only issued to an identified user
        "csrf_token": get_csrf_token(request) if user else "",
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        "user": user,
        "htmx_config": HTMX_CONFIG,
        "is_hx": request.headers.get("hx-request") == "true",
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
    if request.headers.get("hx-request") == "true":
        return Response(status_code=204, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)
