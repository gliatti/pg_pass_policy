"""Unit tests, third review round: commit before the response, IPv4-mapped
proxy peers, bcrypt 72-byte limit, roles truncation, reserved profile
names, full page for a non-htmx form error, superuser flag cached,
shared helpers."""

from __future__ import annotations

import base64
import io
import logging
from contextlib import contextmanager
from types import SimpleNamespace

import bcrypt
import psycopg
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app import auth, db, hashpw
from app.main import create_app
from app.routers import profiles, roles
from tests.conftest import TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings

# --- fakes ----------------------------------------------------------------------------


class _Tx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, events, commit_error=None):
        self.events = events
        self.commit_error = commit_error

    def execute(self, *args, **kwargs):
        return SimpleNamespace(fetchone=lambda: None, fetchall=list)

    def transaction(self):
        return _Tx(self)

    def commit(self):
        self.events.append("commit")


class FakePool:
    """Same exit behaviour as ConnectionPool.connection(): `with conn:`
    commits on success, rolls back on error."""

    def __init__(self, events, commit_error=None):
        self.events = events
        self.commit_error = commit_error

    @contextmanager
    def connection(self):
        conn = FakeConn(self.events)
        try:
            yield conn
        except BaseException:
            self.events.append("rollback")
            raise
        if self.commit_error is not None:
            raise self.commit_error
        self.events.append("commit")


def _app():
    app = create_app(make_settings())
    add_probe_routes(app)

    from app.csrf import get_csrf_token

    @app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    return app


def _recording(app, events):
    """ASGI wrapper recording when the response starts."""

    async def wrapper(scope, receive, send):
        async def recording_send(message):
            if message["type"] == "http.response.start":
                events.append(f"response {message['status']}")
            await send(message)

        await app(scope, receive, recording_send)

    return wrapper


def _client(app, events):
    client = TestClient(_recording(app, events), follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    token = client.get("/_csrf").json()["token"]
    events.clear()
    return client, token


# --- 1: the request transaction is committed before the response starts ---------------


@pytest.mark.parametrize("htmx", [True, False])
def test_profile_create_commits_before_redirect(monkeypatch, htmx):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    monkeypatch.setattr(profiles, "settings_from_form", lambda form: {})
    monkeypatch.setattr(db, "create_profile", lambda conn, name, s: events.append("create"))
    client, token = _client(app, events)
    headers = {"X-CSRF-Token": token, **({"HX-Request": "true"} if htmx else {})}
    response = client.post("/profiles", data={"name": "p1"}, headers=headers)
    assert response.status_code == (204 if htmx else 303)
    # db.run_action() commits right after the action; the request's own
    # commit (an empty transaction by then) also comes before the response
    assert events[:2] == ["create", "commit"]
    assert events[-1] == f"response {response.status_code}"
    assert "rollback" not in events


@pytest.mark.parametrize(
    ("path", "patch"),
    [
        ("/profiles/p/p1/delete", "drop_profile"),
        ("/maintenance/run", "run_maintenance"),
        ("/profiles/assign", "assign_profile"),
    ],
)
def test_write_actions_commit_before_response(monkeypatch, path, patch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    app.state.session_superuser = True
    monkeypatch.setattr(db, patch, lambda conn, *a: events.append("action") or [])
    for name in ("assignments", "login_roles", "profile_names"):
        monkeypatch.setattr(db, name, lambda *a: [])
    client, token = _client(app, events)
    response = client.post(
        path, data={"role": "r", "profile": "p"}, headers={"X-CSRF-Token": token}
    )
    assert response.status_code in (200, 303), response.text
    assert events[:2] == ["action", "commit"]
    assert events[-1].startswith("response")


def test_commit_failure_is_an_error_not_a_redirect(monkeypatch, caplog):
    caplog.set_level(logging.ERROR)
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events, commit_error=psycopg.OperationalError("commit lost"))
    monkeypatch.setattr(db, "drop_profile", lambda conn, name: events.append("drop"))
    client, token = _client(app, events)
    response = client.post(
        "/profiles/p/p1/delete", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 500
    assert "HX-Redirect" not in response.headers
    assert "Database error" in response.text
    assert "commit lost" in caplog.text


def test_every_route_uses_the_function_scope():
    app = _app()
    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for dep in dependant.dependencies:
            if dep.call is db.get_conn:
                assert dep.scope == "function", route.path


# --- 2: IPv4-mapped IPv6 peer ----------------------------------------------------------


def _proxy_app():
    app = create_app(
        make_settings(auth="proxy", basic_users="", trusted_proxies="127.0.0.1, 10.1.0.0/16")
    )
    add_probe_routes(app)
    return app


@pytest.mark.parametrize(
    ("peer", "expected"),
    [
        ("::ffff:127.0.0.1", 200),
        ("::ffff:10.1.2.3", 200),
        ("::ffff:192.168.1.9", 403),
        ("::1", 403),
    ],
)
def test_proxy_ipv4_mapped_peer(peer, expected):
    client = TestClient(_proxy_app(), client=(peer, 40000))
    assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == expected


def test_proxy_mapped_form_listed_as_such():
    app = create_app(
        make_settings(auth="proxy", basic_users="", trusted_proxies="::ffff:127.0.0.1")
    )
    add_probe_routes(app)
    client = TestClient(app, client=("::ffff:127.0.0.1", 40000))
    assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == 200


# --- 3: passwords over 72 bytes are refused, not truncated ----------------------------


def _hash_tool(monkeypatch, capsys, password: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(password + "\n"))
    rc = hashpw.main(["alice"])
    out, err = capsys.readouterr()
    return rc, out, err


def test_hash_tool_refuses_over_72_bytes(monkeypatch, capsys):
    rc, out, err = _hash_tool(monkeypatch, capsys, "é" * 37)  # 37 chars, 74 bytes
    assert rc == 1 and out == ""
    assert "must not exceed 72 bytes" in err
    assert "Traceback" not in err


_REAL_GENSALT = bcrypt.gensalt


def test_hash_tool_accepts_72_bytes(monkeypatch, capsys):
    monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=12: _REAL_GENSALT(rounds=4))
    rc, out, _ = _hash_tool(monkeypatch, capsys, "a" * 72)
    assert rc == 0 and out.startswith("alice:$2b$")
    assert bcrypt.checkpw(b"a" * 72, out.strip().split(":", 1)[1].encode())


def _basic(user: str, password: bytes) -> str:
    return "Basic " + base64.b64encode(user.encode() + b":" + password).decode()


def test_verify_basic_refuses_over_72_bytes():
    prefix = b"p" * 72
    users = {"alice": bcrypt.hashpw(prefix, bcrypt.gensalt(rounds=4))}
    assert auth.verify_basic(_basic("alice", prefix), users) == "alice"
    # truncation would have accepted this one
    assert auth.verify_basic(_basic("alice", prefix + b"x"), users) is None
    assert auth.verify_basic(_basic("ghost", prefix + b"x"), users) is None


# --- 4: no false "truncated" at exactly MAX_ROLES ------------------------------------


@pytest.mark.parametrize(("count", "truncated"), [(db.MAX_ROLES, False), (db.MAX_ROLES + 1, True)])
def test_roles_truncation(monkeypatch, count, truncated):
    calls = []

    def list_roles(conn, status=None, profile=None, search=None, limit=db.MAX_ROLES):
        calls.append(limit)
        return [{"role_name": f"r{i}"} for i in range(min(count, limit))]

    monkeypatch.setattr(db, "list_roles", list_roles)
    monkeypatch.setattr(db, "profile_names", lambda conn: [])
    context = roles._table_context(None, {"status": None, "profile": None, "q": None})
    assert calls == [db.MAX_ROLES + 1]
    assert context["truncated"] is truncated
    assert len(context["roles"]) == db.MAX_ROLES


# --- 5 / 6: reserved profile names, full page outside htmx -----------------------------


@pytest.fixture
def form_app(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    monkeypatch.setattr(db, "create_profile", lambda *a: events.append("create"))
    monkeypatch.setattr(db, "alter_profile", lambda *a: events.append("alter"))
    monkeypatch.setattr(db, "get_profile", lambda conn, name: {"name": name})
    return app, events


@pytest.mark.parametrize("name", sorted(profiles.RESERVED_NAMES))
def test_reserved_name_refused_on_create(form_app, name):
    app, events = form_app
    client, token = _client(app, events)
    response = client.post(
        "/profiles", data={"name": name}, headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 422
    assert "is reserved by the web interface" in response.text
    assert "create" not in events


def test_reserved_name_refused_on_update(form_app):
    app, events = form_app
    client, token = _client(app, events)
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    # "." only arrives encoded (a client removes the plain dot segment)
    response = client.post("/profiles/p/%2E", data={}, headers=headers)
    assert response.status_code == 422
    assert "is reserved by the web interface" in response.text
    assert "alter" not in events
    # "new" is an ordinary name under /profiles/p/: no collision with the
    # fixed GET /profiles/new route
    response = client.post("/profiles/new", data={}, headers=headers)
    assert response.status_code == 405
    assert "alter" not in events


def test_form_error_without_htmx_is_a_full_page(form_app):
    app, events = form_app
    client, token = _client(app, events)
    response = client.post("/profiles", data={"name": "", "csrf_token": token})
    assert response.status_code == 422
    assert "<!doctype html>" in response.text.lower()
    assert "<nav>" in response.text and "New profile</h1>" in response.text
    assert "a profile name is required" in response.text

    response = client.post("/profiles/p/p1", data={"min_length": "x", "csrf_token": token})
    assert response.status_code == 422
    assert "<nav>" in response.text and "Profile p1</h1>" in response.text


def test_form_error_with_htmx_is_the_fragment(form_app):
    app, events = form_app
    client, token = _client(app, events)
    response = client.post(
        "/profiles", data={"name": ""}, headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 422
    assert response.text.lstrip().startswith('<form id="profile-form"')
    assert "<nav>" not in response.text


# --- 9: superuser flag queried once ------------------------------------------------------


def test_session_superuser_is_cached():
    queries = []

    class Conn:
        def execute(self, sql, *args):
            queries.append(sql)
            return SimpleNamespace(fetchone=lambda: {"su": False})

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    assert db.session_is_superuser(request, Conn()) is False
    assert db.session_is_superuser(request, Conn()) is False
    assert len(queries) == 1


# --- 10: shared helpers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Bearer abc", None),
        ("Basic %%%", None),
        ("Basic " + base64.b64encode(b"nocolon").decode(), None),
        ("Basic " + base64.b64encode(b"bob:pw:x").decode(), (b"bob", b"pw:x")),
        ("basic " + base64.b64encode(b":").decode(), (b"", b"")),
    ],
)
def test_decode_basic(header, expected):
    assert auth._decode_basic(header) == expected


def test_basic_user_name_uses_the_same_decoding():
    assert auth.basic_user_name("Basic " + base64.b64encode(b"bob:pw").decode()) == "bob"
    assert auth.basic_user_name("Basic " + base64.b64encode(b"bob").decode()) is None


def test_reread_after_commit(caplog):
    caplog.set_level(logging.ERROR)
    conn = SimpleNamespace(transaction=lambda: _Tx(None))
    log = logging.getLogger("pgpp-web.test")
    assert db.reread_after_commit(conn, lambda c: 42, log, "x", "warn") == (42, None)

    def broken(c):
        raise psycopg.OperationalError("gone")

    assert db.reread_after_commit(conn, broken, log, "role r rotated", "warn") == (None, "warn")
    assert "role r rotated, the re-read failed: gone" in caplog.text


def test_redirect_to():
    app = _app()
    app.state.pool = FakePool([])
    client = TestClient(app, follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    from app.templating import redirect_to

    @app.get("/_go")
    def go(request: Request):
        return redirect_to(request, "profiles")

    response = client.get("/_go")
    assert response.status_code == 303 and response.headers["location"] == "/profiles"
    response = client.get("/_go", headers={"HX-Request": "true"})
    assert response.status_code == 204 and response.headers["HX-Redirect"] == "/profiles"
