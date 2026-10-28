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
from app.auth import dummy_hash, require_user
from app.config import Settings
from app.csrf import InvalidCsrfToken, verify_csrf
from app.db import ExtensionUnavailable, extension_unavailable, make_pool
from app.logfilter import get_logger, install_log_masking
from app.routers import audit, dashboard, maintenance, pairs, profiles, roles
from app.security import SecurityHeadersMiddleware
from app.templating import STATIC_DIR, alert_response, is_hx, render

log = get_logger("main")


def create_app(settings: Settings | None = None) -> FastAPI:
    install_log_masking()
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
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
    if settings.auth == "basic":
        # computed now rather than on the first unknown user (one bcrypt run)
        dummy_hash(settings.basic_user_hashes())
    # outermost first: security headers wrap everything, the session sits inside
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret.get_secret_value(),
        session_cookie=session_cookie_name(settings),
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
        headers = exc.headers
        detail = str(exc.detail)
        if isinstance(exc, InvalidCsrfToken):
            has_cookie = session_cookie_name(settings) in request.cookies
            if not exc.supplied:
                # no token: a client that never fetched a page; without the
                # session cookie either, say that it must be kept as well
                if not has_cookie:
                    detail = f"{detail}. {SESSION_NOT_STORED}"
            elif secure_cookie_over_http(request, settings):
                # a Secure cookie the browser drops (page served over plain
                # HTTP): a reload would fail the same way on every action
                detail = SESSION_NOT_STORED
            elif is_hx(request):
                # a stale token (session expired or lost while the page
                # stayed open): reload the page for a fresh one
                headers = {**(headers or {}), "HX-Refresh": "true"}
        return _error_response(request, exc.status_code, detail, headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Any:
        # an HTML page or fragment, never FastAPI's JSON body (htmx would
        # swap it into the page as text)
        return _error_response(request, 422, validation_detail(exc))

    @app.exception_handler(PoolTimeout)
    async def pool_timeout(request: Request, exc: PoolTimeout) -> Any:
        log.error("database unavailable: %s", exc)
        return _error_response(request, 503, "Database unavailable")

    # one handler for every PostgreSQL error, logged once with its SQLSTATE:
    # an unavailable extension (extension_unavailable(): a 55000 of the
    # first query reaching the shared memory when the library is not
    # preloaded, a 3F000 / 55000 when it is not installed in the database)
    # gets its dedicated page, anything else the generic 500 page
    @app.exception_handler(psycopg.Error)
    async def db_error(request: Request, exc: psycopg.Error) -> Any:
        missing = extension_unavailable(exc)
        cause = f" (from: {exc.__cause__})" if exc.__cause__ is not None else ""
        if missing is not None:
            label, _ = UNAVAILABLE_PAGES[missing.reason]
            log.error(
                "pg_pass_policy is not %s (%s %s) [SQLSTATE %s]: %s%s",
                label,
                request.method,
                request.url.path,
                exc.sqlstate,
                exc,
                cause,
            )
            return _unavailable_response(request, missing)
        # the full text (table names, libpq connection details...) goes to the
        # server log only, never to the browser
        log.error(
            "database error on %s %s [SQLSTATE %s]: %s%s",
            request.method,
            request.url.path,
            exc.sqlstate,
            exc,
            cause,
        )
        return _error_response(request, 500, "Database error, see the server log")

    return app


# shown without automatic reload: a cookie the browser does not keep would
# make HX-Refresh fail again on every action
SESSION_NOT_STORED = (
    "Session cookie not stored (or expired): reload the page; if this persists,"
    " check PGPP_WEB_SESSION_HTTPS_ONLY / cookies (a Secure cookie is not kept"
    " over plain HTTP, the browser may block cookies)"
)


def secure_cookie_over_http(request: Request, settings: Settings) -> bool:
    """A Secure session cookie (PGPP_WEB_SESSION_HTTPS_ONLY) and a page the
    browser loaded over plain HTTP (Origin, else Referer, as the browser
    sees it, whatever the proxy in between): the cookie is never stored."""
    if not settings.session_https_only:
        return False
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    return origin.lower().startswith("http://")


def session_cookie_name(settings: Settings) -> str:
    """The session cookie: the __Host- prefix (Secure, Path=/, no Domain)
    stops a same-site origin from planting its own session cookie on the
    host, it requires a Secure cookie."""
    return "__Host-pgpp_session" if settings.session_https_only else "pgpp_session"


def validation_detail(exc: RequestValidationError) -> str:
    """'Invalid request: length: Input should be ...' (field names and
    messages only: the submitted values are not echoed back)."""
    parts = []
    for error in exc.errors():
        loc = [str(x) for x in error.get("loc", ()) if x not in ("body", "query", "path")]
        field = ".".join(loc) or "request"
        parts.append(f"{field}: {error.get('msg', 'invalid value')}")
    return "Invalid request: " + ("; ".join(parts) or "invalid value")


# global alert container of base.html: htmx error fragments are swapped there
ALERTS_TARGET = "#alerts"


# each ExtensionUnavailable.reason: (state named in the log, page template)
UNAVAILABLE_PAGES: dict[str, tuple[str, str]] = {
    "not_preloaded": ("preloaded", "not_preloaded.html"),
    "not_installed": ("installed", "not_installed.html"),
}


def _unavailable_response(request: Request, missing: ExtensionUnavailable) -> Any:
    """The "extension not preloaded" or "extension not installed" page (503),
    with the server's message and HINT; an alert in the page's alert area
    for htmx."""
    if is_hx(request) or not getattr(request.state, "user", None):
        detail = missing.message + (f" (hint: {missing.hint})" if missing.hint else "")
        return _error_response(request, 503, detail)
    return render(
        request,
        UNAVAILABLE_PAGES[missing.reason][1],
        {"message": missing.message, "hint": missing.hint},
        status_code=503,
    )


def _error_response(
    request: Request, status_code: int, detail: str, headers: dict[str, str] | None = None
) -> Any:
    if is_hx(request):
        # the fragment is a bare alert, not what the triggering element
        # expects (a role row, a form...): it goes to the page's alert area
        # so that the target stays in place
        headers = {**(headers or {}), "HX-Retarget": ALERTS_TARGET, "HX-Reswap": "innerHTML"}
        if status_code == 401:
            # htmx cannot answer a basic-auth challenge: ask for a full reload
            headers["HX-Refresh"] = "true"
        return alert_response(request, detail, status_code, headers)
    # no navigation for an unidentified client: the router's 404 / 405 and
    # the 401 / 403 of the authentication are raised before (or instead of)
    # require_user, request.state.user is then unset
    template = "error.html" if getattr(request.state, "user", None) else "error_anonymous.html"
    return render(
        request,
        template,
        {"status_code": status_code, "detail": detail},
        status_code=status_code,
        headers=headers,
    )
