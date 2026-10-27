"""CSRF protection: a per-session token, bound to the authenticated user and
checked on every unsafe request.

The token lives in the signed session cookie (Starlette SessionMiddleware,
secret PGPP_WEB_SECRET) together with the name of the user it was issued to,
and must be sent back either as the X-CSRF-Token header (HTMX, via hx-headers
on <body>) or as the csrf_token form field.  Binding the token to the user
defeats cookie tossing: a session planted by a same-site attacker (or obtained
anonymously) is never accepted together with the credentials the browser
sends on its own (HTTP basic, proxy header).
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request, status

CSRF_HEADER = "x-csrf-token"
CSRF_FIELD = "csrf_token"
SESSION_KEY = "csrf"
SESSION_USER_KEY = "csrf_user"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# the back-office has no legitimate same-site caller (another subdomain or
# port of the same site): only same-origin requests, or a non-browser client
# that sends no Sec-Fetch-Site header, may submit
REFUSED_FETCH_SITES = frozenset({"cross-site", "same-site"})


def get_csrf_token(request: Request) -> str:
    user = getattr(request.state, "user", None)
    token = request.session.get(SESSION_KEY)
    # (re)issue the token when none exists or when it was issued to another
    # identity (including the anonymous page shown before authentication)
    if not token or request.session.get(SESSION_USER_KEY) != user:
        token = secrets.token_urlsafe(32)
        request.session[SESSION_KEY] = token
        request.session[SESSION_USER_KEY] = user
    return token


async def verify_csrf(request: Request) -> None:
    """FastAPI dependency: reject unsafe requests without a valid token.

    Declared after require_user in the application dependencies, so
    request.state.user is already set.
    """
    if request.method in SAFE_METHODS:
        return
    if request.headers.get("sec-fetch-site", "").lower() in REFUSED_FETCH_SITES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-site request refused")
    user = getattr(request.state, "user", None)
    expected = request.session.get(SESSION_KEY)
    bound_user = request.session.get(SESSION_USER_KEY)
    supplied = request.headers.get(CSRF_HEADER)
    if supplied is None:
        # media types are case-insensitive (RFC 9110 §8.3.1)
        content_type = request.headers.get("content-type", "").lower()
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()
            value = form.get(CSRF_FIELD)
            supplied = value if isinstance(value, str) else None
    if (
        not expected
        or not supplied
        or not user
        or bound_user != user
        # bytes: compare_digest() raises TypeError on non-ASCII str
        or not hmac.compare_digest(expected.encode(), supplied.encode())
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
