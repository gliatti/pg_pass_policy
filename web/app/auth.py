"""Authentication: HTTP basic (bcrypt hashes) or a reverse-proxy header."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import ipaddress
import re

import bcrypt
from fastapi import HTTPException, Request, status

from app.config import Settings, bcrypt_cost
from app.hashpw import BCRYPT_MAX_BYTES
from app.logfilter import get_logger
from app.security import route_path

log = get_logger("auth")

# paths served without authentication (liveness probe for the reverse proxy)
PUBLIC_PATHS = frozenset({"/healthz"})

# cost of the dummy hash when no user is configured (proxy mode never uses it)
DEFAULT_COST = 12


@functools.cache
def _dummy_hash_of_cost(cost: int) -> bytes:
    return bcrypt.hashpw(b"pgpp-web dummy", bcrypt.gensalt(rounds=cost))


def dummy_hash(users: dict[str, bytes]) -> bytes:
    """A valid bcrypt hash of a fixed value, compared against when the user is
    unknown so that the response time does not reveal whether the user
    exists.  Its cost is that of the first configured hash: config.Settings
    requires every hash of PGPP_WEB_BASIC_USERS to share it, a dummy of
    another cost would answer faster or slower than a real check.  Computed
    once per cost (create_app() computes it at startup)."""
    first = next(iter(users.values()), None)
    cost = bcrypt_cost(first) if first is not None else None
    return _dummy_hash_of_cost(cost or DEFAULT_COST)


# a user name: 1 to 128 characters, none of them a C0 or C1 control character
# (U+0000-U+001F, U+007F-U+009F) or a line / paragraph separator (U+2028,
# U+2029), which a log viewer or a terminal may render as a line break
_USER_RE = re.compile(r"^[^\x00-\x1f\x7f-\x9f  ]{1,128}$")

# session key of the cached basic authentication (see _basic_fingerprint())
SESSION_BASIC_KEY = "basic_auth"


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
    return _verify_decoded(*decoded, users)


def _verify_decoded(user_b: bytes, password_b: bytes, users: dict[str, bytes]) -> str | None:
    """verify_basic() on the (user, password) bytes of a decoded header."""
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
        valid = bcrypt.checkpw(password_b, digest or dummy_hash(users))
    except ValueError:
        valid = False
    if digest is None or not valid:
        return None
    return user


def _basic_fingerprint(settings: Settings, authorization: str, digest: bytes) -> str:
    """HMAC-SHA256, keyed with PGPP_WEB_SECRET, of the Authorization header
    and of the bcrypt hash it was checked against.

    Stored in the session after a successful bcrypt check, so that the next
    requests of the same browser (which sends the same header every time)
    skip bcrypt: a bcrypt check costs tens of milliseconds by design, paid
    on every request otherwise.  The session cookie is signed, not
    encrypted: it holds this keyed fingerprint only, never the header or the
    password, and the fingerprint cannot be checked against a guessed
    password without the secret.  A change of the header (another user,
    another password) gives another fingerprint, and so does a change of
    the hash in PGPP_WEB_BASIC_USERS (password changed, user removed: the
    user has no hash any more): the cache is then ignored and bcrypt runs
    again."""
    key = settings.secret.get_secret_value().encode()
    message = b"pgpp-web basic\x00" + authorization.encode("latin-1", "replace") + b"\x00" + digest
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _cached_basic_user(
    request: Request,
    settings: Settings,
    authorization: str,
    claimed: str | None = None,
) -> str | None:
    """The user of a session whose cached fingerprint matches this header.

    claimed: the user name of the header, when the caller already decoded
    it (authenticate_basic()); decoded here otherwise."""
    cached = request.session.get(SESSION_BASIC_KEY)
    if not isinstance(cached, dict):
        return None
    user, fingerprint = cached.get("user"), cached.get("fp")
    if not isinstance(user, str) or not isinstance(fingerprint, str):
        return None
    digest = settings.basic_user_hashes().get(user)
    if claimed is None:
        claimed = basic_user_name(authorization)
    if digest is None or claimed != user:
        return None
    expected = _basic_fingerprint(settings, authorization, digest)
    return user if hmac.compare_digest(fingerprint, expected) else None


def authenticate_basic(request: Request, settings: Settings) -> str | None:
    """verify_basic() on the Authorization header, skipped when the session
    holds the fingerprint of the same header (_basic_fingerprint()).  A
    failed check drops the cached fingerprint.  The header is decoded once,
    for both steps."""
    authorization = request.headers.get("authorization")
    decoded = _decode_basic(authorization)
    if not authorization or decoded is None:
        request.session.pop(SESSION_BASIC_KEY, None)
        return None
    user_b, password_b = decoded
    claimed = user_b.decode("utf-8", "replace")
    user = _cached_basic_user(request, settings, authorization, claimed)
    if user is not None:
        return user
    users = settings.basic_user_hashes()
    user = _verify_decoded(user_b, password_b, users)
    if user is None:
        request.session.pop(SESSION_BASIC_KEY, None)
        return None
    request.session[SESSION_BASIC_KEY] = {
        "user": user,
        "fp": _basic_fingerprint(settings, authorization, users[user]),
    }
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
    # Starlette decodes header values as latin-1 (the HTTP default): the
    # reverse proxy sends the user name in UTF-8, so "Émilie" would arrive
    # as "Ã\x89milie".  The original bytes are recovered (latin-1 maps each
    # byte to one character) and decoded as UTF-8.  Bytes that are not valid
    # UTF-8 keep their latin-1 reading (the behaviour before UTF-8 decoding,
    # for a proxy that sends latin-1), with a warning: the same name may
    # then come from two different headers ("É" as C3 89 or as C9).
    raw = request.headers.get(header) or ""
    try:
        user = raw.encode("latin-1").decode("utf-8").strip()
    except UnicodeError:
        log.warning("proxy header %s is not valid UTF-8: read as latin-1", header)
        user = raw.strip()
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
        user = authenticate_basic(request, settings)
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
