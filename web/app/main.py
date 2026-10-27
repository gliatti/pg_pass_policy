"""FastAPI application factory: `uvicorn app.main:create_app --factory`."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import psycopg
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import PoolTimeout
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.auth import require_user
from app.config import Settings
from app.csrf import verify_csrf
from app.db import make_pool
from app.logfilter import get_logger, install_log_masking
from app.routers import audit, dashboard, maintenance, pairs, profiles, roles
from app.security import SecurityHeadersMiddleware
from app.templating import STATIC_DIR, render

log = get_logger("main")


def create_app(settings: Settings | None = None) -> FastAPI:
    install_log_masking()
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        install_log_masking()  # uvicorn's handlers exist by now
        pool = make_pool(settings)
        pool.open(wait=False)
        app.state.pool = pool
        log.info("pgpp-web %s started (auth=%s)", __version__, settings.auth)
        try:
            yield
        finally:
            pool.close()

    app = FastAPI(
        title="pg_pass_policy back-office",
        version=__version__,
        lifespan=lifespan,
        dependencies=[Depends(require_user), Depends(verify_csrf)],
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    # outermost first: security headers wrap everything, the session sits inside
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret.get_secret_value(),
        # the __Host- prefix (Secure, Path=/, no Domain) stops a same-site
        # origin from planting its own session cookie on the host
        session_cookie="__Host-pgpp_session" if settings.session_https_only else "pgpp_session",
        same_site="strict",
        https_only=settings.session_https_only,
        max_age=8 * 3600,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(dashboard.router)
    app.include_router(roles.router)
    app.include_router(profiles.router)
    app.include_router(audit.router)
    app.include_router(pairs.router)
    app.include_router(maintenance.router)

    @app.get("/healthz", response_class=PlainTextResponse, name="healthz")
    def healthz() -> str:
        return "ok"

    # Starlette's class: also catches the 404 / 405 raised by the router
    # itself (fastapi.HTTPException is a subclass)
    @app.exception_handler(StarletteHTTPException)
    async def http_exception(request: Request, exc: StarletteHTTPException) -> Any:
        return _error_response(request, exc.status_code, str(exc.detail), exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Any:
        # an HTML page or fragment, never FastAPI's JSON body (htmx would
        # swap it into the page as text)
        return _error_response(request, 422, validation_detail(exc))

    @app.exception_handler(PoolTimeout)
    async def pool_timeout(request: Request, exc: PoolTimeout) -> Any:
        log.error("database unavailable: %s", exc)
        return _error_response(request, 503, "Database unavailable")

    @app.exception_handler(psycopg.Error)
    async def db_error(request: Request, exc: psycopg.Error) -> Any:
        # the full text (table names, libpq connection details...) goes to the
        # server log only, never to the browser
        log.error("database error on %s %s: %s", request.method, request.url.path, exc)
        return _error_response(request, 500, "Database error, see the server log")

    return app


def validation_detail(exc: RequestValidationError) -> str:
    """'Invalid request: length: Input should be ...' (field names and
    messages only: the submitted values are not echoed back)."""
    parts = []
    for error in exc.errors():
        loc = [str(x) for x in error.get("loc", ()) if x not in ("body", "query", "path")]
        field = ".".join(loc) or "request"
        parts.append(f"{field}: {error.get('msg', 'invalid value')}")
    return "Invalid request: " + ("; ".join(parts) or "invalid value")


def _error_response(
    request: Request, status_code: int, detail: str, headers: dict[str, str] | None = None
) -> Any:
    if status_code == 401 and request.headers.get("hx-request") == "true":
        # htmx cannot answer a basic-auth challenge: ask for a full reload
        headers = {**(headers or {}), "HX-Refresh": "true"}
    if request.headers.get("hx-request") == "true":
        return render(
            request, "_alert.html", {"error": detail}, status_code=status_code, headers=headers
        )
    if "session" not in request.scope:
        # outside the middleware stack (should not happen): plain text
        return PlainTextResponse(detail, status_code=status_code, headers=headers)
    return render(
        request,
        "error.html",
        {"status_code": status_code, "detail": detail},
        status_code=status_code,
        headers=headers,
    )
