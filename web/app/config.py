"""Application settings, read from PGPP_WEB_* environment variables."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import PrivateAttr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.usernames import user_name_problem

_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")
_BCRYPT_COST_RE = re.compile(rb"^\$2[aby]\$([0-9]{2})\$")
# a whole bcrypt hash: $2b$NN$, then 22 characters of salt and 31 of digest
# in bcrypt's base64 alphabet (60 characters in all)
_BCRYPT_HASH_RE = re.compile(rb"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}")
MIN_SECRET_LENGTH = 32


def bcrypt_cost(digest: bytes) -> int | None:
    """The cost of a bcrypt hash ($2b$12$... -> 12), None if unreadable."""
    match = _BCRYPT_COST_RE.match(digest)
    cost = int(match.group(1)) if match else None
    return cost if cost is not None and 4 <= cost <= 31 else None


def _malformed_hash(user: str, digest: str) -> str:
    return (
        f"PGPP_WEB_BASIC_USERS: the bcrypt hash of {user!r} is truncated or malformed"
        f" ({len(digest)} characters, 60 expected: $2b$NN$ then 53 characters"
        " of [./A-Za-z0-9]): rehash with pgpp-web-hash"
    )


# accepted values of PGPP_WEB_PROXY_HEADER_ENCODING (case-insensitive)
PROXY_HEADER_ENCODINGS = ("utf-8", "latin-1")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PGPP_WEB_", extra="ignore")

    # libpq connection string; empty = use the PG* environment variables
    database_url: str = ""
    # authentication mode: HTTP basic or a header set by a reverse proxy
    auth: Literal["basic", "proxy"] = "basic"
    # "user:bcrypt-hash,user2:bcrypt-hash" (see `pgpp-web-hash`)
    basic_users: str = ""
    # header carrying the authenticated user in proxy mode (REMOTE_USER is
    # accepted and mapped to Remote-User)
    proxy_header: str = "X-Remote-User"
    # encoding of the proxy header value: "utf-8" or "latin-1"; a value not
    # valid in this encoding is refused (401), never read in another one
    proxy_header_encoding: str = "utf-8"
    # comma separated IP addresses / networks allowed to set the proxy header;
    # "*" trusts every peer (not recommended), "unix" trusts Unix socket peers
    trusted_proxies: str = "127.0.0.1,::1"
    # signing key of the session cookie (CSRF token); at least 32 characters
    secret: SecretStr
    # mark the session cookie Secure (set it behind HTTPS)
    session_https_only: bool = False
    realm: str = "pg_pass_policy"
    pool_min: int = 1
    pool_max: int = 4
    pool_timeout: float = 10.0
    page_size: int = 50
    # application_name prefix recorded in pass_policy.audit_log
    app_name: str = "pgpp-web"

    # parsed once by _check(), read on every request by the authentication
    _user_hashes: dict[str, bytes] = PrivateAttr(default_factory=dict)
    _networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = PrivateAttr(
        default_factory=list
    )
    _proxy_tokens: frozenset[str] = PrivateAttr(default_factory=frozenset)

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if len(self.secret.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"PGPP_WEB_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        self._user_hashes = self._parse_basic_users()
        if self.auth == "basic" and not self._user_hashes:
            raise ValueError("PGPP_WEB_BASIC_USERS must list at least one user:bcrypt-hash")
        self._networks = self._parse_trusted_networks()  # also validates the syntax
        self._proxy_tokens = frozenset(t.strip() for t in self.trusted_proxies.split(","))
        encoding = self.proxy_header_encoding.strip().lower()
        if encoding not in PROXY_HEADER_ENCODINGS:
            raise ValueError(
                "PGPP_WEB_PROXY_HEADER_ENCODING must be utf-8 or latin-1"
                f" (got {self.proxy_header_encoding!r})"
            )
        self.proxy_header_encoding = encoding
        if self.page_size < 1 or self.page_size > 1000:
            raise ValueError("PGPP_WEB_PAGE_SIZE must be between 1 and 1000")
        self._check_pool()
        return self

    def _check_pool(self) -> None:
        """Pool bounds that psycopg_pool would refuse late (at the first
        connection) or accept with a surprising effect: a pool that can never
        open a connection, a timeout that fails every wait at once."""
        if self.pool_min < 0:
            raise ValueError(f"PGPP_WEB_POOL_MIN must be 0 or more (got {self.pool_min})")
        if self.pool_max < 1:
            raise ValueError(f"PGPP_WEB_POOL_MAX must be 1 or more (got {self.pool_max})")
        if self.pool_max < self.pool_min:
            raise ValueError(
                f"PGPP_WEB_POOL_MAX ({self.pool_max}) must be at least"
                f" PGPP_WEB_POOL_MIN ({self.pool_min})"
            )
        # not (> 0) also refuses NaN, which every comparison rejects
        if not self.pool_timeout > 0 or self.pool_timeout == float("inf"):
            raise ValueError(
                f"PGPP_WEB_POOL_TIMEOUT must be a positive number of seconds"
                f" (got {self.pool_timeout})"
            )

    def basic_user_hashes(self) -> dict[str, bytes]:
        """{user: bcrypt hash} from PGPP_WEB_BASIC_USERS (parsed at startup)."""
        return self._user_hashes

    def trusted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Networks of PGPP_WEB_TRUSTED_PROXIES (parsed at startup)."""
        return self._networks

    def trust_all_proxies(self) -> bool:
        return "*" in self._proxy_tokens

    def trust_unix_peer(self) -> bool:
        return "unix" in self._proxy_tokens

    def _parse_basic_users(self) -> dict[str, bytes]:
        """Parse PGPP_WEB_BASIC_USERS into {user: bcrypt hash}."""
        users: dict[str, bytes] = {}
        for entry in self.basic_users.split(","):
            entry = entry.strip()
            if not entry:
                continue
            user, sep, digest = entry.partition(":")
            if not sep or not user or not digest.startswith(_BCRYPT_PREFIXES):
                raise ValueError("PGPP_WEB_BASIC_USERS entries must be user:bcrypt-hash")
            # the rule of the proxy header (app.usernames): a name that
            # could never be told apart from another one in a log line
            problem = user_name_problem(user)
            if problem is not None:
                raise ValueError(f"PGPP_WEB_BASIC_USERS: user name {user!r} refused: {problem}")
            if not digest.isascii():
                raise ValueError(_malformed_hash(user, digest))
            if user in users:
                # the last entry would silently replace the first one
                raise ValueError(f"PGPP_WEB_BASIC_USERS: user {user!r} is listed more than once")
            users[user] = digest.encode("ascii")
        # one cost for every hash: an unknown user is checked against a dummy
        # hash of that cost (auth.dummy_hash()), a user whose hash had another
        # cost would be told apart from an unknown one by the response time
        costs = {bcrypt_cost(d) for d in users.values()}
        if None in costs:
            raise ValueError("PGPP_WEB_BASIC_USERS: unreadable bcrypt cost (expected $2b$NN$...)")
        if len(costs) > 1:
            raise ValueError(
                "PGPP_WEB_BASIC_USERS: every bcrypt hash must have the same cost"
                f" (found {', '.join(str(c) for c in sorted(costs))}): rehash with pgpp-web-hash"
            )
        # a truncated or mangled hash (cut by a shell, a quote, a line wrap)
        # would be accepted above and make bcrypt.checkpw() raise "Invalid
        # salt" at the first login of that user: refused at startup instead
        for user, digest in users.items():
            if not _BCRYPT_HASH_RE.fullmatch(digest):
                raise ValueError(_malformed_hash(user, digest.decode("ascii")))
        return users

    def _parse_trusted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for token in self.trusted_proxies.split(","):
            token = token.strip()
            if token in ("", "*", "unix"):
                continue
            networks.append(ipaddress.ip_network(token, strict=False))
        return networks

    def proxy_header_name(self) -> str:
        """HTTP header name, lower case; REMOTE_USER (CGI style) maps to remote-user."""
        return self.proxy_header.strip().replace("_", "-").lower()
