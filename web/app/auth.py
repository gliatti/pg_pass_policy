"""Authentication: HTTP basic (bcrypt hashes) or a reverse-proxy header."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import ipaddress
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime

import bcrypt
from fastapi import HTTPException, Request, status

from app.config import Settings, bcrypt_cost
from app.hashpw import BCRYPT_MAX_BYTES
from app.logfilter import get_logger
from app.security import route_path
from app.usernames import user_name_problem, valid_user_name

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


# characters of a claimed user name kept in a log line
LOGGED_NAME_MAX = 64


def _loggable(user: str | None) -> str:
    """A claimed user name safe for a log line, valid or not: cut to
    LOGGED_NAME_MAX characters, then quoted and escaped by json.dumps()
    (always double quotes, " and \\ escaped, every control or non-ASCII
    character escaped as \\n or \\uXXXX, DEL too), followed by "..." when cut.  Pure
    ASCII, at most 6 * 2 * LOGGED_NAME_MAX + 5 characters.  Always quoted,
    so that no name can forge the " from <address>" that follows it in a
    log line, nor slip an invisible or look-alike character into the log."""
    if user is None:
        return "<none>"
    quoted = json.dumps(user[:LOGGED_NAME_MAX]).replace("\x7f", "\\u007f")
    return quoted + ("..." if len(user) > LOGGED_NAME_MAX else "")


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


def _ipv4_of_mapped(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """The IPv4 form of an IPv4-mapped IPv6 address (uvicorn --host ::
    reports an IPv4 peer as ::ffff:127.0.0.1), None for any other address."""
    if isinstance(addr, ipaddress.IPv6Address):
        return addr.ipv4_mapped
    return None


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
    # an IPv4-mapped peer matches its IPv4 form too (and the mapped form
    # itself, if listed as such)
    candidates = [addr]
    mapped = _ipv4_of_mapped(addr)
    if mapped is not None:
        candidates.append(mapped)
    return any(a in net for a in candidates for net in settings.trusted_networks())


def _peer(request: Request) -> str:
    """The peer of a request, for a log line: its address, "unix" for a
    Unix socket peer (no client, or an empty host)."""
    client = request.client
    return client.host if client is not None and client.host else "unix"


def _peer_key(request: Request) -> str:
    """The throttling key of a peer: its address normalised, so that one
    source cannot open a window per address it can use.  An IPv4-mapped
    address is its IPv4 form, an IPv6 address its /64 (the usual
    allocation of a single site); "unix" or a host that is not an address
    as is."""
    peer = _peer(request)
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    mapped = _ipv4_of_mapped(addr)
    if mapped is not None:
        return str(mapped)
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Window:
    """The throttling state of one key of a _ThrottledWarning."""

    last: float | None = None
    suppressed: int = 0
    since: datetime | None = None

    def add(self, count: int, since: datetime | None) -> None:
        """Count `count` suppressed warnings, the first one at `since` (now if
        None, read only when no count is pending)."""
        if not count:
            return
        if not self.suppressed:
            self.since = since or _utcnow()
        elif since is not None:
            self.since = min(self.since or since, since)
        self.suppressed += count

    def take(self) -> tuple[int, datetime | None]:
        taken = self.suppressed, self.since
        self.suppressed, self.since = 0, None
        return taken


# lines a _ThrottledWarning logs per interval, all keys together
MAX_LINES_PER_INTERVAL = 20


class _ThrottledWarning:
    """A warning logged at most once per `interval` seconds and per key (a
    flood of bad requests must not flood the log).  The next line logged
    for a key tells how many were suppressed since the first suppressed
    one; flush() (at shutdown) logs the counts still pending.

    The key (the peer address, say) keeps one source from hiding another:
    each key has its own window.  At most `max_lines` lines are logged per
    interval, all keys together: beyond, the warnings are added to a single
    global count, logged in one line with the first warning of a later
    interval, or by flush().  At most `max_keys` keys are tracked, the
    least recently seen one is dropped beyond (its pending count goes to
    the global count, no line of its own), so that a scan from many
    addresses can neither grow the state nor flood the log."""

    def __init__(
        self,
        label: str,
        interval: float = 60.0,
        max_keys: int = 256,
        max_lines: int = MAX_LINES_PER_INTERVAL,
    ):
        self.label = label
        self.interval = interval
        self.max_keys = max_keys
        self.max_lines = max_lines
        self._lock = threading.Lock()
        self._windows: OrderedDict[str, _Window] = OrderedDict()
        # the global window: its start, the lines logged in it, and the
        # count suppressed beyond max_lines or dropped with a key
        self._global_start: float | None = None
        self._global_lines = 0
        self._global = _Window()

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._global_start, self._global_lines = None, 0
            self._global = _Window()

    def _subject(self, key: str) -> str:
        return f"{self.label} {key}" if key else self.label

    def _log_pending(self, subject: str, suppressed: int, since: datetime | None) -> None:
        if suppressed and since is not None:
            log.warning(
                "%s: %d similar warnings suppressed since %s",
                subject,
                suppressed,
                since.isoformat(timespec="seconds"),
            )

    def _global_subject(self) -> str:
        return f"{self.label} (all sources)"

    def warning(self, message: str, *args: object, key: str = "") -> None:
        now = time.monotonic()
        global_pending: tuple[int, datetime | None] = (0, None)
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = self._windows[key] = _Window()
                if len(self._windows) > self.max_keys:
                    _, old = self._windows.popitem(last=False)
                    self._global.add(*old.take())
            else:
                self._windows.move_to_end(key)
            if window.last is not None and now - window.last < self.interval:
                window.add(1, None)
                return
            window.last = now
            if self._global_start is None or now - self._global_start >= self.interval:
                self._global_start, self._global_lines = now, 0
                global_pending = self._global.take()
            if self._global_lines >= self.max_lines:
                # over the global cap: this warning and the count of its key
                # go to the global count
                self._global.add(*window.take())
                self._global.add(1, None)
                return
            self._global_lines += 1
            suppressed, since = window.take()
        self._log_pending(self._global_subject(), *global_pending)
        if suppressed and since is not None:
            message += " (%d similar warnings suppressed since %s)"
            args = (*args, suppressed, since.isoformat(timespec="seconds"))
        log.warning(message, *args)

    def flush(self) -> None:
        """Log the counts of warnings suppressed and not reported yet, if any:
        one line for each of the first `max_lines` keys, the others added to
        the global count."""
        with self._lock:
            pending = [(key, *window.take()) for key, window in self._windows.items()]
            pending = [entry for entry in pending if entry[1]]
            for _, suppressed, since in pending[self.max_lines :]:
                self._global.add(suppressed, since)
            global_pending = self._global.take()
        for key, suppressed, since in pending[: self.max_lines]:
            self._log_pending(self._subject(key), suppressed, since)
        self._log_pending(self._global_subject(), *global_pending)


# peers tracked by the untrusted peer warning (least recently seen dropped)
UNTRUSTED_PEERS_TRACKED = 256


class AuthWarnings:
    """The throttled warnings of one application (app.state.auth_warnings,
    set by create_app(), flushed by its lifespan): two applications in one
    process (tests, a reload) never share nor flush each other's counts."""

    def __init__(self) -> None:
        # a proxy header that cannot be decoded: a misconfigured reverse
        # proxy or PGPP_WEB_PROXY_HEADER_ENCODING, worth a trace (never the
        # header itself)
        self.undecodable_proxy_header = _ThrottledWarning("proxy header not decodable")
        # a proxy header sent by a peer outside PGPP_WEB_TRUSTED_PROXIES:
        # once per minute and per peer at most, a scan or a misrouted client
        # would send one per request; per peer, so that one noisy address
        # does not hide the others
        self.untrusted_proxy_peer = _ThrottledWarning(
            "proxy header refused from untrusted peer", max_keys=UNTRUSTED_PEERS_TRACKED
        )
        # a proxy header holding a name refused by app.usernames (NFKC,
        # invisible character...): the reason and the escaped name, per
        # escaped name (the peer is the trusted proxy, nearly always one)
        self.refused_proxy_user = _ThrottledWarning(
            "proxy header user name refused", max_keys=UNTRUSTED_PEERS_TRACKED
        )

    def all(self) -> tuple[_ThrottledWarning, ...]:
        return (self.undecodable_proxy_header, self.untrusted_proxy_peer, self.refused_proxy_user)

    def flush(self) -> None:
        """At shutdown: report the warnings suppressed since the last one logged."""
        for throttled in self.all():
            throttled.flush()


def user_from_proxy(request: Request, settings: Settings) -> str:
    warnings: AuthWarnings = request.app.state.auth_warnings
    if not _client_is_trusted(request, settings):
        peer, key = _peer(request), _peer_key(request)
        # the key too when it differs (an IPv6 /64), so that the count
        # suppressed with this line is credited to the key
        warnings.untrusted_proxy_peer.warning(
            "proxy header refused from untrusted peer %s",
            peer if key == peer else f"{peer} ({key})",
            key=key,
        )
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
        warnings.undecodable_proxy_header.warning(
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
    problem = user_name_problem(user)
    if problem is not None:
        logged = _loggable(user)
        warnings.refused_proxy_user.warning(
            "proxy header user name %s refused from peer %s: %s",
            logged,
            _peer(request),
            problem,
            key=logged,
        )
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
