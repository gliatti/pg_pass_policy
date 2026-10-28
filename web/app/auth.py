"""Authentication: HTTP basic (bcrypt hashes) or a reverse-proxy header."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import ipaddress
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import bcrypt
from fastapi import HTTPException, Request, status

from app.config import Settings, bcrypt_cost
from app.hashpw import BCRYPT_MAX_BYTES
from app.logfilter import get_logger
from app.security import route_path
from app.usernames import valid_user_name

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


def _valid_user(name: str) -> bool:
    """A user name, under the rule of app.usernames (also applied to
    PGPP_WEB_BASIC_USERS at startup)."""
    return valid_user_name(name)


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


def _loggable(user: str | None) -> str:
    """A user name safe for a log line: no control characters, bounded length."""
    if user is None:
        return "<none>"
    return user if _valid_user(user) else repr(user)[:128]


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
    request: Request, settings: Settings, authorization: str, claimed: str
) -> str | None:
    """The user of a session whose cached fingerprint matches this header.

    claimed: the user name of the header, decoded by the caller
    (authenticate_basic())."""
    cached = request.session.get(SESSION_BASIC_KEY)
    if not isinstance(cached, dict):
        return None
    user, fingerprint = cached.get("user"), cached.get("fp")
    if not isinstance(user, str) or not isinstance(fingerprint, str):
        return None
    digest = settings.basic_user_hashes().get(user)
    if digest is None or claimed != user:
        return None
    expected = _basic_fingerprint(settings, authorization, digest)
    return user if hmac.compare_digest(fingerprint, expected) else None


@dataclass(frozen=True)
class BasicResult:
    """Outcome of authenticate_basic(): the authenticated user (None on
    failure) and the user name claimed by the header (None when there is no
    well-formed Basic header), decoded once for both."""

    user: str | None
    claimed: str | None


def authenticate_basic(request: Request, settings: Settings) -> BasicResult:
    """verify_basic() on the Authorization header, skipped when the session
    holds the fingerprint of the same header (_basic_fingerprint()).  A
    failed check drops the cached fingerprint.  The header is decoded once,
    for both steps and for the caller's log line."""
    authorization = request.headers.get("authorization")
    decoded = _decode_basic(authorization)
    if decoded is None:
        request.session.pop(SESSION_BASIC_KEY, None)
        return BasicResult(None, None)
    user_b, password_b = decoded
    # unverified, for the cache check and the log line
    claimed = user_b.decode("utf-8", "replace")
    user = _cached_basic_user(request, settings, authorization, claimed)
    if user is not None:
        return BasicResult(user, claimed)
    users = settings.basic_user_hashes()
    user = _verify_decoded(user_b, password_b, users)
    if user is None:
        request.session.pop(SESSION_BASIC_KEY, None)
        return BasicResult(None, claimed)
    request.session[SESSION_BASIC_KEY] = {
        "user": user,
        "fp": _basic_fingerprint(settings, authorization, users[user]),
    }
    return BasicResult(user, claimed)


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


def _peer(request: Request) -> str:
    """The peer of a request, for a log line: its address, "unix" for a
    Unix socket peer (no client, or an empty host)."""
    client = request.client
    return client.host if client is not None and client.host else "unix"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _ThrottledWarning:
    """A warning logged at most once per `interval` seconds (a flood of bad
    requests must not flood the log).  The next line logged tells how many
    were suppressed since the first suppressed one; flush() (at shutdown)
    logs a count still pending."""

    def __init__(self, label: str, interval: float = 60.0):
        self.label = label
        self.interval = interval
        self._lock = threading.Lock()
        self._last: float | None = None
        self._suppressed = 0
        self._since: datetime | None = None

    def reset(self) -> None:
        with self._lock:
            self._last, self._suppressed, self._since = None, 0, None

    def _take(self) -> tuple[int, datetime | None]:
        # caller holds the lock
        taken = self._suppressed, self._since
        self._suppressed, self._since = 0, None
        return taken

    def warning(self, message: str, *args: object) -> None:
        now = time.monotonic()
        with self._lock:
            if self._last is not None and now - self._last < self.interval:
                if not self._suppressed:
                    self._since = _utcnow()
                self._suppressed += 1
                return
            self._last = now
            suppressed, since = self._take()
        if suppressed and since is not None:
            message += " (%d similar warnings suppressed since %s)"
            args = (*args, suppressed, since.isoformat(timespec="seconds"))
        log.warning(message, *args)

    def flush(self) -> None:
        """Log the count of warnings suppressed and not reported yet, if any."""
        with self._lock:
            suppressed, since = self._take()
        if suppressed and since is not None:
            log.warning(
                "%s: %d similar warnings suppressed since %s",
                self.label,
                suppressed,
                since.isoformat(timespec="seconds"),
            )


# a proxy header that cannot be decoded: a misconfigured reverse proxy or
# PGPP_WEB_PROXY_HEADER_ENCODING, worth a trace (never the header itself)
_undecodable_proxy_header = _ThrottledWarning("proxy header not decodable")
# a proxy header sent by a peer outside PGPP_WEB_TRUSTED_PROXIES: logged
# once per minute at most, a scan or a misrouted client would send one per
# request
_untrusted_proxy_peer = _ThrottledWarning("proxy header refused from untrusted peer")

THROTTLED_WARNINGS = (_undecodable_proxy_header, _untrusted_proxy_peer)


def flush_throttled_warnings() -> None:
    """At shutdown: report the warnings suppressed since the last one logged."""
    for throttled in THROTTLED_WARNINGS:
        throttled.flush()


def user_from_proxy(request: Request, settings: Settings) -> str:
    if not _client_is_trusted(request, settings):
        _untrusted_proxy_peer.warning("proxy header refused from untrusted peer %s", _peer(request))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requests must come through the trusted reverse proxy",
        )
    header = settings.proxy_header_name()
    encoding = settings.proxy_header_encoding
    # Starlette decodes header values as latin-1 (each byte to one
    # character): the original bytes are recovered and decoded strictly in
    # the configured encoding (PGPP_WEB_PROXY_HEADER_ENCODING), never in
    # another one, so that each name comes from a single byte sequence.
    # Only ASCII blanks are stripped, on the bytes, before decoding, and
    # nothing after: str.strip() would also drop \xa0 or \x85 (bytes of
    # UTF-8 sequences: "à" is C3 A0) or, after decoding, a no-break or an
    # ideographic space, so that several byte sequences would give the same
    # name.  A name holding such a space is refused by _valid_user().
    raw = (request.headers.get(header) or "").strip(" \t")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (proxy header missing)",
        )
    try:
        user = raw.encode("latin-1").decode(encoding)
    except UnicodeError:
        _undecodable_proxy_header.warning(
            "proxy header %s not valid %s (%d bytes) from %s",
            header,
            encoding,
            len(raw),
            _peer(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated (proxy header not valid {encoding})",
        ) from None
    if not _valid_user(user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (proxy header not a valid user name)",
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
        result = authenticate_basic(request, settings)
        user = result.user
        if user is None:
            if authorization:
                # one line per failure (user and peer, never the password) so
                # that the reverse proxy or fail2ban can throttle the source
                log.warning(
                    "basic authentication failed for user %s from %s",
                    _loggable(result.claimed),
                    _peer(request),
                )
            raise _unauthorized(settings, "Not authenticated")
    else:
        user = user_from_proxy(request, settings)
    request.state.user = user
    return user
