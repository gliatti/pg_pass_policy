"""Unit tests, second review round: htmx error retargeting, anonymous error
page, password shown when the re-read fails, worker_status() errors,
route_path() == Starlette's get_route_path()."""

from __future__ import annotations

import psycopg
import pytest
from fastapi import Query, Request
from fastapi.testclient import TestClient
from starlette._utils import get_route_path  # private: used by this test only

from app import db
from app.main import create_app
from app.security import route_path
from tests.conftest import TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings

PASSWORD = "Rotated-Pw-0123456789xyz"


@pytest.fixture
def app():
    app = create_app(make_settings())
    add_probe_routes(app)

    from app.csrf import get_csrf_token

    @app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    @app.get("/_page")
    def page(n: int = Query(ge=1)) -> dict[str, int]:
        return {"n": n}

    return app


def authed(app) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    client.auth = (TEST_USER, TEST_PASSWORD)
    token = client.get("/_csrf").json()["token"]
    return client, {"X-CSRF-Token": token, "HX-Request": "true"}


# --- 6: route_path() is Starlette's rule -------------------------------------------


@pytest.mark.parametrize(
    ("path", "root_path"),
    [
        ("/", ""),
        ("", ""),
        ("/healthz", ""),
        ("/pgpp", "/pgpp"),
        ("/pgpp/", "/pgpp"),
        ("/pgpp/healthz", "/pgpp"),
        ("/pgpp/static/app.css", "/pgpp"),
        ("/pgppx/healthz", "/pgpp"),
        ("/pgppx", "/pgpp"),
        ("/healthz", "/pgpp"),
        ("/", "/pgpp"),
        ("/a/b", "/a"),
        ("/a/b/", "/a/b"),
        ("/pgpp/", "/pgpp/"),
        ("/pgpp//x", "/pgpp/"),
    ],
)
def test_route_path_matches_starlette(path, root_path):
    scope = {"type": "http", "path": path, "root_path": root_path}
    assert route_path(scope) == get_route_path(scope)


def test_route_path_without_root_path_key():
    scope = {"type": "http", "path": "/pgpp/x"}
    assert route_path(scope) == get_route_path(scope) == "/pgpp/x"


# --- 3: htmx error fragments go to the alert area -------------------------------------


def test_htmx_validation_error_is_retargeted(app):
    client, headers = authed(app)
    response = client.get("/_page", params={"n": "0"}, headers=headers)
    assert response.status_code == 422
    assert response.headers["HX-Retarget"] == "#alerts"
    assert response.headers["HX-Reswap"] == "innerHTML"
    assert "Invalid request: n:" in response.text


def test_htmx_router_error_is_retargeted(app):
    client, headers = authed(app)
    response = client.delete("/healthz", headers=headers)
    assert response.status_code == 405
    assert response.headers["HX-Retarget"] == "#alerts"


def test_htmx_401_reloads_and_is_retargeted(app):
    response = TestClient(app).get("/_whoami", headers={"HX-Request": "true"})
    assert response.status_code == 401
    assert response.headers["HX-Refresh"] == "true"
    assert response.headers["HX-Retarget"] == "#alerts"


def test_non_htmx_error_is_not_retargeted(app):
    client, _ = authed(app)
    response = client.get("/_page", params={"n": "0"})
    assert response.status_code == 422
    assert "HX-Retarget" not in response.headers


def test_pages_have_the_alert_area(app):
    @app.get("/_missing_after_auth")
    def missing() -> None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="nothing here")

    client, _ = authed(app)
    response = client.get("/_missing_after_auth")
    assert response.status_code == 404
    assert '<div id="alerts" aria-live="polite"></div>' in response.text


# --- 4: no navigation for an unidentified client --------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [("get", "/no/such/page", 404), ("delete", "/healthz", 405), ("get", "/_whoami", 401)],
)
def test_anonymous_error_page_is_minimal(app, method, path, status):
    response = getattr(TestClient(app), method)(path)
    assert response.status_code == status
    assert f"Error {status}" in response.text
    assert "<nav>" not in response.text and "Dashboard" not in response.text
    assert 'href="/roles"' not in response.text
    assert 'name="csrf-token"' not in response.text
    assert "set-cookie" not in response.headers


def test_router_404_is_minimal_even_with_credentials(app):
    # the router fails before require_user: the user is not known
    client, _ = authed(app)
    response = client.get("/no/such/page")
    assert response.status_code == 404 and "<nav>" not in response.text


def test_identified_user_error_page_has_navigation(app):
    @app.get("/_missing_after_auth")
    def missing() -> None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="nothing here")

    client, _ = authed(app)
    response = client.get("/_missing_after_auth")
    assert response.status_code == 404
    assert "<nav>" in response.text and "signed in as" in response.text


# --- 2: the password is shown even when the re-read fails ----------------------------


class _Tx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.events.append("savepoint")
        return self

    def __exit__(self, *exc):
        self.conn.events.append("rollback" if exc[0] else "release")
        return False


class _Conn:
    def __init__(self):
        self.events: list[str] = []

    def transaction(self):
        return _Tx(self)

    def commit(self):
        self.events.append("commit")


@pytest.fixture
def fake_conn(app):
    conn = _Conn()
    app.dependency_overrides[db.get_conn] = lambda: conn
    return conn


def _broken_read(conn, *args):
    conn.events.append("reread")
    raise psycopg.OperationalError("server closed the connection unexpectedly")


def test_rotate_shows_password_when_reread_fails(app, fake_conn, monkeypatch, caplog):
    def rotate(conn, role, length):
        conn.events.append("rotate")
        return PASSWORD

    monkeypatch.setattr(db, "rotate_password", rotate)
    monkeypatch.setattr(db, "get_role", _broken_read)
    client, headers = authed(app)
    response = client.post("/roles/app%2Fbatch/rotate", data={"length": "24"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert f'class="secret">{PASSWORD}</code>' in response.text
    assert "could not be read back" in response.text
    assert "app/batch" in response.text
    assert "is not a login role" not in response.text
    # committed before the re-read, which runs in its own (failed) block
    assert fake_conn.events == [
        "savepoint",
        "rotate",
        "release",
        "commit",
        "savepoint",
        "reread",
        "rollback",
    ]
    assert PASSWORD not in caplog.text


def test_rotate_error_is_not_masked(app, fake_conn, monkeypatch):
    """Without a password (rotation refused), a failing re-read is still an error."""

    def refuse(conn, role, length):
        raise psycopg.errors.RaiseException("PPP-010 password too recent")

    monkeypatch.setattr(db, "rotate_password", refuse)
    monkeypatch.setattr(db, "get_role", _broken_read)
    client, headers = authed(app)
    response = client.post("/roles/x/rotate", headers=headers)
    assert response.status_code == 500
    assert "Database error" in response.text


def test_switch_shows_password_when_reread_fails(app, fake_conn, monkeypatch, caplog):
    def switch(conn, pair, length):
        conn.events.append("switch")
        return {
            "active_role": "app_b",
            "password": PASSWORD,
            "previous_role": "app_a",
            "previous_valid_until": None,
        }

    monkeypatch.setattr(db, "switch_pair", switch)
    monkeypatch.setattr(db, "list_pairs", _broken_read)
    client, headers = authed(app)
    response = client.post("/pairs/p%2F1/switch", headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert f'class="secret">{PASSWORD}</code>' in response.text
    assert "could not be read back" in response.text
    assert "Pair list unavailable." in response.text
    assert "active role is now <code>app_b</code>" in response.text
    assert fake_conn.events == [
        "savepoint",
        "switch",
        "release",
        "commit",
        "savepoint",
        "reread",
        "rollback",
    ]
    assert PASSWORD not in caplog.text


# --- 5: worker_status() only absorbs the worker's own errors ------------------------


class _WorkerConn(_Conn):
    def __init__(self, exc):
        super().__init__()
        self.exc = exc

    def execute(self, *args, **kwargs):
        raise self.exc


def test_worker_status_unavailable_returns_none():
    exc = psycopg.errors.ObjectNotInPrerequisiteState("pg_pass_policy worker state unavailable")
    conn = _WorkerConn(exc)
    assert db.worker_status(conn) is None  # type: ignore[arg-type]
    assert conn.events == ["savepoint", "rollback"]


def test_worker_status_not_preloaded_propagates():
    exc = psycopg.errors.ObjectNotInPrerequisiteState(
        "pg_pass_policy shared memory is not initialized"
    )
    conn = _WorkerConn(exc)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        db.worker_status(conn)  # type: ignore[arg-type]
    assert conn.events == ["savepoint", "rollback"]


@pytest.mark.parametrize(
    "exc",
    [
        # a missing function or privilege gives None (see test_review_round8)
        psycopg.OperationalError("server closed the connection unexpectedly"),
        psycopg.errors.AdminShutdown("terminating connection due to administrator command"),
        psycopg.InterfaceError("the connection is closed"),
    ],
)
def test_worker_status_connection_errors_propagate(exc):
    with pytest.raises(type(exc)):
        db.worker_status(_WorkerConn(exc))  # type: ignore[arg-type]
