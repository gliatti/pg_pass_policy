"""Unit tests, fifteenth review round: UTF-8 proxy user names, C1 controls and
line separators refused in user names, audit pagination without
count(*) OVER (), basic authentication cached in the session, rotation
without a password, worker status re-read after a maintenance run, since
filter checked before the query, pool settings validated."""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from types import SimpleNamespace

import psycopg
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app import auth, db
from app.main import create_app
from app.routers import audit, maintenance, roles
from tests.conftest import TEST_HASH, TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings
from tests.test_review_round6 import _client, _raise
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)

# --- 8: the proxy header is decoded as UTF-8 -----------------------------------------------


def _proxy_client() -> TestClient:
    app = create_app(make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User"))
    add_probe_routes(app)
    return TestClient(app, client=("127.0.0.1", 40000))


def test_a_utf8_proxy_user_is_decoded():
    client = _proxy_client()
    # what a reverse proxy sends: the UTF-8 bytes of the name
    response = client.get("/_whoami", headers={"X-Remote-User": "Émilie".encode()})
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "Émilie"}
    # plain ASCII is unchanged
    assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).json() == {"user": "carol"}


def _proxy_request(raw: bytes) -> Request:
    """A request carrying these exact header bytes (the test client would
    re-encode a non-UTF-8 value: httpx decodes it as latin-1, then the
    transport encodes it as UTF-8)."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/_whoami",
        "headers": [(b"x-remote-user", raw)],
        "client": ("127.0.0.1", 40000),
    }
    return Request(scope)


# --- 9: C1 controls and line separators are refused in a user name -------------------------


@pytest.mark.parametrize(
    "name",
    [
        "a\x85b",
        "a\x9bb",
        "a\x80",
        "a\u2028b",
        "a\u2029b",
        "a\x7fb",
        # Unicode spaces and format characters, inside or at the end
        "a\xa0b",
        "bob\xa0",
        "bob\u3000",
        "\u3000bob",
        "bob\x85",
        "a\u200bb",
        "a\u202eb",
        "a\xadb",
        # ASCII space at either end
        " bob",
        "bob ",
        "",
    ],
)
def test_c1_controls_and_separators_are_refused(name):
    assert not auth._valid_user(name)
    assert auth._loggable(name) == repr(name)[:128]
    # (ASCII blanks around a proxy header are stripped, on the bytes)
    if name and name.strip(" ") == name:
        response = _proxy_client().get("/_whoami", headers={"X-Remote-User": name.encode()})
        assert response.status_code == 401


@pytest.mark.parametrize("name", ["Émilie", "zoë", "E\u0301milie", "a b", "日本", "x" * 128])
def test_printable_names_are_accepted(name):
    assert auth._valid_user(name)
    assert auth._loggable(name) == name
    assert not auth._valid_user("x" * 129)


# --- 10: audit pagination ------------------------------------------------------------------


class _AuditConn:
    """Answers the single audit query with `matching` events, as PostgreSQL
    would: the rows past `offset` (at most LIMIT), or one row with NULL page
    columns when the page is empty, and the bounded count min(matching, cap)
    only when the page is full or past the end (NULL otherwise)."""

    def __init__(self, matching: int):
        self.matching = matching
        self.queries: list[tuple[str, dict]] = []
        self.counted = 0

    def execute(self, sql, params):
        self.queries.append((sql, params))
        limit, offset = params["limit"], params["offset"]
        assert params["limit1"] == limit + 1
        page = list(range(offset, min(self.matching, offset + limit + 1)))
        n = None
        if len(page) > limit or (not page and offset > 0):
            self.counted += 1
            n = min(self.matching, params["cap"])
        rows = [{"matching": n, "id": i} for i in page] or [{"matching": n, "id": None}]
        return SimpleNamespace(fetchall=lambda: rows)


def test_audit_queries_one_row_more_and_never_counts_over():
    conn = _AuditConn(30)
    page = db.list_audit(conn, limit=50, offset=0)
    sql, params = conn.queries[0]
    assert "OVER" not in sql and (params["limit1"], params["offset"]) == (51, 0)
    # last page: one statement, the total without a count
    assert page == db.AuditPage(page.rows, 30)
    assert len(page.rows) == 30 and len(conn.queries) == 1 and conn.counted == 0
    assert "matching" not in page.rows[0]


def test_audit_nothing_matches_is_one_query():
    conn = _AuditConn(0)
    assert db.list_audit(conn, limit=50, offset=0) == db.AuditPage([], 0)
    assert len(conn.queries) == 1 and conn.counted == 0


def test_audit_page_and_count_are_one_statement_up_to_the_cap():
    conn = _AuditConn(120)
    page = db.list_audit(conn, role="r", limit=50, offset=50)
    assert len(page.rows) == 50 and page.has_next and page.total == 120 and not page.capped
    assert len(conn.queries) == 1 and conn.counted == 1
    sql, params = conn.queries[0]
    assert "LIMIT %(limit1)s" in sql and "LIMIT %(cap)s" in sql
    # the rows of the page are counted once, the filter appears twice
    assert sql.count("FROM p)") == 1 and sql.count("role_name = %(role)s") == 2
    assert params == {
        "role": "r",
        "limit1": 51,
        "limit": 50,
        "offset": 50,
        "cap": db.AUDIT_COUNT_CAP + 1,
    }

    conn = _AuditConn(25_000)
    page = db.list_audit(conn, limit=50, offset=0)
    assert page.capped and page.has_next and page.total == db.AUDIT_COUNT_CAP + 1
    assert audit.total_label(page) == "10,000+"


def test_the_last_page_beyond_the_cap_is_shown_capped_too():
    conn = _AuditConn(25_000)
    page = db.list_audit(conn, limit=50, offset=24_950)
    assert len(page.rows) == 50 and not page.has_next
    assert page.capped and audit.total_label(page) == "10,000+"
    # not full: no count, the total is bounded as a count would be
    assert page.total == db.AUDIT_COUNT_CAP + 1 and conn.counted == 0


def test_audit_page_past_the_end_is_counted_up_to_the_cap_only():
    conn = _AuditConn(25_000)
    page = db.list_audit(conn, limit=50, offset=30_000)
    assert page == db.AuditPage([], db.AUDIT_COUNT_CAP + 1, capped=True)
    assert len(conn.queries) == 1


def test_a_capped_audit_is_paged_with_next_only(app, monkeypatch):  # noqa: F811
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        seen.append(offset)
        rows = [{"id": 1, "event_type": "auth_failed"}]
        return db.AuditPage(rows, db.AUDIT_COUNT_CAP + 1, capped=True, has_next=True)

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _client(app)
    response = client.get("/audit/table", params={"page": "300"})
    assert response.status_code == 200
    # not clamped to the cap: page 300 is shown, without a page count
    assert seen == [299 * 50]
    assert "10,000+ events — page 300</p>" in response.text
    assert "&page=301" in response.text and "&page=299" in response.text
    assert "page 300 / " not in response.text


# --- 14: since: invalid dates and bare numbers ---------------------------------------------


@pytest.mark.parametrize("text", ["2026-13-45", "2026-02-30", "2026-10-27T25:00", "2026-1-5"])
def test_an_invalid_date_is_refused(text):
    with pytest.raises(db.InvalidFilter, match="invalid date"):
        db.parse_since(text)


@pytest.mark.parametrize("text", ["7", " 30 ", "-3", "1.5", "20261345", "202610"])
def test_a_bare_number_needs_a_unit(text):
    with pytest.raises(db.InvalidFilter, match="needs a unit"):
        db.parse_since(text)


def test_valid_since_values():
    assert db.parse_since("2026-10-27").day == 27
    assert db.parse_since("2026-10-27T10:00").hour == 10
    # eight digits forming a valid date are a date (ISO basic form)
    assert db.parse_since("20261027") == datetime(2026, 10, 27)
    assert db.parse_since("7 days") == "7 days"
    assert db.parse_since("1 hour 30 minutes") == "1 hour 30 minutes"
    assert db.parse_since("  ") is None


def test_an_invalid_since_is_shown_without_a_query(app, monkeypatch):  # noqa: F811
    monkeypatch.setattr(db, "list_audit", _raise(AssertionError("no query")))
    client, _ = _client(app)
    response = client.get("/audit/table", params={"since": "2026-13-01"})
    assert response.status_code == 200
    assert "Invalid filter: since &#39;2026-13-01&#39;: invalid date" in response.text
    response = client.get("/audit/table", params={"since": "7"})
    assert "needs a unit" in response.text


# --- 11: basic authentication cached in the session ----------------------------------------


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_basic_auth_is_cached_in_the_session(unit_app, monkeypatch):
    calls: list[bytes] = []
    real = auth._verify_decoded
    decodes: list[str | None] = []
    real_decode = auth._decode_basic

    def counting(user_b, password_b, users):
        calls.append(user_b)
        return real(user_b, password_b, users)

    def counting_decode(authorization):
        decodes.append(authorization)
        return real_decode(authorization)

    monkeypatch.setattr(auth, "_verify_decoded", counting)
    monkeypatch.setattr(auth, "_decode_basic", counting_decode)
    client = TestClient(unit_app)
    good = {"Authorization": _basic(TEST_USER, TEST_PASSWORD)}
    for _ in range(3):
        assert client.get("/_whoami", headers=good).json() == {"user": TEST_USER}
    assert len(calls) == 1, "bcrypt runs once, then the session fingerprint is used"
    # the header is decoded once per request (cache check and bcrypt check)
    assert len(decodes) == 3
    # the cookie holds a keyed fingerprint, never the header nor the password
    cookie = client.cookies.get("pgpp_session")
    payload = base64.b64decode(cookie.split(".")[0] + "==")
    assert TEST_PASSWORD.encode() not in payload
    assert good["Authorization"].split()[1].encode() not in payload

    # another header: the cache does not apply, a wrong password is refused
    bad = {"Authorization": _basic(TEST_USER, "wrong-password")}
    assert client.get("/_whoami", headers=bad).status_code == 401
    assert len(calls) == 2
    # the failure dropped the cache: the good header is checked again
    assert client.get("/_whoami", headers=good).status_code == 200
    assert len(calls) == 3
    assert client.get("/_whoami", headers=good).status_code == 200
    assert len(calls) == 3


def test_the_basic_cache_follows_the_configured_hash():
    settings = make_settings()
    header = _basic(TEST_USER, TEST_PASSWORD)
    fp = auth._basic_fingerprint(settings, header, TEST_HASH.encode())
    # another hash (password changed in PGPP_WEB_BASIC_USERS), another
    # header or another secret: another fingerprint
    assert fp != auth._basic_fingerprint(settings, header, b"$2b$04$" + b"x" * 53)
    assert fp != auth._basic_fingerprint(settings, _basic(TEST_USER, "other"), TEST_HASH.encode())
    other = make_settings(secret="another-unit-test-secret-of-32-characters")
    assert fp != auth._basic_fingerprint(other, header, TEST_HASH.encode())

    def request(cached, authorization=header, s=settings):
        return SimpleNamespace(session={auth.SESSION_BASIC_KEY: cached}), authorization, s

    def cached_user(cached, **kw):
        req, authorization, s = request(cached, **kw)
        return auth._cached_basic_user(
            req, s, authorization, auth._decode_basic(authorization)[0].decode()
        )

    assert cached_user({"user": TEST_USER, "fp": fp}) == TEST_USER
    # a user no longer configured, a forged user name, a malformed entry
    assert (
        cached_user({"user": TEST_USER, "fp": fp}, s=make_settings(basic_users=f"bob:{TEST_HASH}"))
        is None
    )
    assert cached_user({"user": "bob", "fp": fp}) is None
    assert cached_user({"user": TEST_USER, "fp": "0" * 64}) is None
    assert cached_user("garbage") is None
    assert cached_user({"user": 1, "fp": fp}) is None


# --- 12: a committed rotation without a password -------------------------------------------


@pytest.mark.parametrize("password", [None, ""])
def test_a_rotation_without_a_password_is_a_warning(app, monkeypatch, caplog, password):  # noqa: F811
    caplog.set_level(logging.ERROR)
    events: list[str] = []
    monkeypatch.setattr(db, "rotate_password", lambda conn, role, length: password)
    monkeypatch.setattr(db, "get_role", lambda conn, role: events.append("get_role") or None)
    client, token = _client(app)
    response = client.post(
        "/roles/app/rotate", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert roles.NO_PASSWORD_WARNING.format("app").split(",")[0] in response.text
    assert "None" not in response.text
    assert 'class="secret"' not in response.text
    assert "role app: rotation applied but no password returned" in caplog.text
    assert events == ["get_role"]


def test_a_rotation_without_a_password_survives_a_failed_reread(app, monkeypatch, caplog):  # noqa: F811
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(db, "rotate_password", lambda conn, role, length: None)
    monkeypatch.setattr(db, "get_role", _raise(psycopg.OperationalError("connection lost")))
    client, token = _client(app)
    response = client.post(
        "/roles/app/rotate", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert roles.NO_PASSWORD_WARNING.format("app").split(",")[0] in response.text
    assert "could not be read back" in response.text
    assert "role app rotated, the re-read failed: connection lost" in caplog.text


# --- 13: worker status re-read after a maintenance run -------------------------------------


def test_a_failed_worker_status_after_maintenance_is_a_warning(app, monkeypatch, caplog):  # noqa: F811
    caplog.set_level(logging.ERROR)
    actions = [{"action": "purge_audit", "role_name": None, "details": {"rows": 3}}]
    monkeypatch.setattr(db, "run_maintenance", lambda conn: actions)
    monkeypatch.setattr(db, "worker_status", _raise(psycopg.OperationalError("connection lost")))
    client, token = _client(app)
    response = client.post(
        "/maintenance/run", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert "Maintenance completed: 1 action." in response.text
    assert "purge_audit" in response.text
    assert maintenance.REREAD_WARNING in response.text
    assert "maintenance run, the re-read failed: connection lost" in caplog.text


def test_the_worker_status_after_maintenance_is_shown(app, monkeypatch):  # noqa: F811
    monkeypatch.setattr(db, "run_maintenance", lambda conn: [])
    monkeypatch.setattr(db, "worker_status", lambda conn: {"pid": 4242, "last_run": None})
    client, token = _client(app)
    response = client.post(
        "/maintenance/run", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200
    assert "Worker pid 4242" in response.text
    assert maintenance.REREAD_WARNING not in response.text


# --- 15: pool settings ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"pool_min": -1}, "PGPP_WEB_POOL_MIN must be 0 or more"),
        ({"pool_min": 0, "pool_max": 0}, "PGPP_WEB_POOL_MAX must be 1 or more"),
        ({"pool_min": 5, "pool_max": 2}, r"PGPP_WEB_POOL_MAX \(2\) must be at least"),
        ({"pool_timeout": 0}, "PGPP_WEB_POOL_TIMEOUT must be a positive"),
        ({"pool_timeout": -1.5}, "PGPP_WEB_POOL_TIMEOUT must be a positive"),
        ({"pool_timeout": float("nan")}, "PGPP_WEB_POOL_TIMEOUT must be a positive"),
        ({"pool_timeout": float("inf")}, "PGPP_WEB_POOL_TIMEOUT must be a positive"),
    ],
)
def test_invalid_pool_settings_are_refused(overrides, message):
    with pytest.raises(ValueError, match=message):
        make_settings(**overrides)


def test_valid_pool_settings():
    make_settings(pool_min=0, pool_max=1, pool_timeout=0.5)
    make_settings(pool_min=4, pool_max=4)
