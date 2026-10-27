"""Authentication: HTTP basic (bcrypt hashes) or a reverse-proxy header."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re

import bcrypt
from fastapi import HTTPException, Request, status

from app.config import Settings
from app.hashpw import BCRYPT_MAX_BYTES
from app.logfilter import get_logger
from app.security import route_path

log = get_logger("auth")

# paths served without authentication (liveness probe for the reverse proxy)
PUBLIC_PATHS = frozenset({"/healthz"})

# a valid bcrypt hash of a random value: used when the user is unknown so that
# the response time does not reveal whether the user exists
_DUMMY_HASH = bcrypt.hashpw(b"pgpp-web dummy", bcrypt.gensalt(rounds=12))

_USER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")


def _unauthorized(settings: Settings, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": f'Basic realm="{settings.realm}", charset="UTF-8"'},
    )


def _decode_basic(authorization: str | None) -> tuple[bytes, bytes] | None:
    """(user, password) bytes of a well-formed Basic header, else None."""
    scheme, _, payload = (authorization or "").partition(" ")
    if scheme.lower() != "basic" or not payload:
        return None
    try:
        decoded = base64.b64decode(payload.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    user_b, sep, password_b = decoded.partition(b":")
    if not sep:
        return None
    return user_b, password_b


def basic_user_name(authorization: str | None) -> str | None:
    """The user name claimed by a Basic header (for logging only, unverified)."""
    decoded = _decode_basic(authorization)
    if decoded is None:
        return None
    return decoded[0].decode("utf-8", "replace")


def _loggable(user: str | None) -> str:
    """A user name safe for a log line: no control characters, bounded length."""
    if user is None:
        return "<none>"
    return user if _USER_RE.match(user) else repr(user)[:128]


def verify_basic(authorization: str | None, users: dict[str, bytes]) -> str | None:
    """Return the user name if the Authorization header holds valid credentials."""
    decoded = _decode_basic(authorization)
    if decoded is None:
        return None
    user_b, password_b = decoded
    try:
        user = user_b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(password_b) > BCRYPT_MAX_BYTES:
        # refused, not truncated (pgpp-web-hash never hashes such a password);
        # the length does not depend on the user: nothing leaks
        return None
    digest = users.get(user)
    # always run bcrypt (constant work), compare against a dummy hash if unknown
    try:
        valid = bcrypt.checkpw(password_b, digest or _DUMMY_HASH)
    except ValueError:
        valid = False
    if digest is None or not valid:
        return None
    return user


def _client_is_trusted(request: Request, settings: Settings) -> bool:
    if settings.trust_all_proxies():
        return True
    client = request.client
    if client is None or not client.host:
        return settings.trust_unix_peer()
    try:
        addr = ipaddress.ip_address(client.host)
    except ValueError:
        return False
    # uvicorn --host :: reports an IPv4 peer as ::ffff:127.0.0.1: match its
    # IPv4 form too (and the mapped form itself, if listed as such)
    candidates = [addr]
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        candidates.append(addr.ipv4_mapped)
    return any(a in net for a in candidates for net in settings.trusted_networks())


def user_from_proxy(request: Request, settings: Settings) -> str:
    if not _client_is_trusted(request, settings):
        log.warning("proxy header refused from untrusted peer %s", request.client)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requests must come through the trusted reverse proxy",
        )
    header = settings.proxy_header_name()
    user = (request.headers.get(header) or "").strip()
    if not user or not _USER_RE.match(user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (proxy header missing)",
        )
    return user


def require_user(request: Request) -> str:
    """FastAPI dependency: authenticate the request and expose the user name."""
    settings: Settings = request.app.state.settings
    if route_path(request.scope) in PUBLIC_PATHS:
        request.state.user = None
        return ""
    if settings.auth == "basic":
        authorization = request.headers.get("authorization")
        user = verify_basic(authorization, settings.basic_user_hashes())
        if user is None:
            if authorization:
                # one line per failure (user and peer, never the password) so
                # that the reverse proxy or fail2ban can throttle the source
                log.warning(
                    "basic authentication failed for user %s from %s",
                    _loggable(basic_user_name(authorization)),
                    request.client.host if request.client else "unix",
                )
            raise _unauthorized(settings, "Not authenticated")
    else:
        user = user_from_proxy(request, settings)
    request.state.user = user
    return user
