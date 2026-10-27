"""Security response headers (CSP with per-request nonce, anti-framing, no-store)."""

from __future__ import annotations

import secrets

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

STATIC_PREFIX = "/static/"


def route_path(scope: Scope) -> str:
    """The request path without the --root-path prefix.

    ASGI servers (uvicorn >= 0.26) put the root_path in front of scope["path"]:
    the application compares its own paths (/healthz, /static/...) against
    this value, never against request.url.path.  Same rule as Starlette's
    router (starlette._utils.get_route_path, private).
    """
    path: str = scope.get("path", "")
    root_path: str = scope.get("root_path", "")
    if root_path and path.startswith(root_path):
        rest = path[len(root_path) :]
        if rest == "" or rest.startswith("/"):
            return rest or "/"
    return path


def csp_for(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        nonce = secrets.token_urlsafe(16)
        scope.setdefault("state", {})["csp_nonce"] = nonce
        is_static = route_path(scope).startswith(STATIC_PREFIX)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("Content-Security-Policy", csp_for(nonce))
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                if is_static:
                    headers.setdefault("Cache-Control", "public, max-age=3600")
                else:
                    # the whole back-office is private; fragments carrying a
                    # password additionally set this header themselves
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)
