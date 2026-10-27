"""Unit tests, sixth review round: "extension not preloaded" page, errors
shown inline only when they come from the extension, profile_edit guard and
404, re-read warning helper."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from types import SimpleNamespace

import psycopg
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app import db
from app.main import create_app
from app.routers import profiles
from tests.conftest import TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings

HINT = "Add pg_pass_policy to shared_preload_libraries and restart the server."


def _diag(sqlstate, message, hint=None):
    return SimpleNamespace(
        sqlstate=sqlstate, message_primary=message, message_detail=None, message_hint=hint
    )


class NotPreloaded(psycopg.errors.ObjectNotInPrerequisiteState):
    """A 55000 carrying the diagnostics of the server (message, HINT)."""

    def __init__(self, message="pg_pass_policy shared memory is not initialized", hint=HINT):
        super().__init__(message)
        self._diag = _diag("55000", message, hint)

    @property
    def diag(self):  # type: ignore[override]
        return self._diag


class _Tx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.events.append("savepoint")
        return self

    def __exit__(self, *exc):
        self.conn.events.append("rollback" if exc[0] else "release")
        return False


class FakeConn:
    def __init__(self, events):
        self.events = events

    def execute(self, *args, **kwargs):
        return SimpleNamespace(fetchone=lambda: None, fetchall=list)

    def transaction(self):
        return _Tx(self)

    def commit(self):
        self.events.append("commit")


class FakePool:
    def __init__(self, events):
        self.events = events

    @contextmanager
    def connection(self):
        try:
            yield FakeConn(self.events)
        except BaseException:
            self.events.append("request rollback")
            raise


@pytest.fixture
def app():
    app = create_app(make_settings())
    add_probe_routes(app)
    app.state.pool = FakePool([])

    from app.csrf import get_csrf_token

    @app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    return app


def _client(app) -> tuple[TestClient, str]:
    client = TestClient(app, follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    return client, client.get("/_csrf").json()["token"]


def _raise(exc):
    def raiser(*args, **kwargs):
        raise exc

    return raiser


# --- 1: extension not preloaded -------------------------------------------------------


def test_not_preloaded_detection():
    assert db.extension_unavailable(NotPreloaded()) is not None
    no_hint = NotPreloaded("pg_pass_policy must be loaded via shared_preload_libraries", None)
    assert db.extension_unavailable(no_hint).message.startswith("pg_pass_policy must be loaded")
    # another 55000 of the extension is not this state
    untrusted = NotPreloaded("PPP-004: pg_pass_policy schema is not trusted", None)
    assert db.extension_unavailable(untrusted) is None
    assert db.extension_unavailable(psycopg.errors.UndefinedTable("relation x")) is None


def test_dashboard_without_preload_is_the_dedicated_page(app, monkeypatch, caplog):
    """v_role_status raises first (failed_attempts()): worker_status() is never
    reached, the request gets the dedicated page with the server's HINT."""
    caplog.set_level(logging.ERROR)
    reached = []
    monkeypatch.setattr(db, "status_counts", _raise(NotPreloaded()))
    monkeypatch.setattr(db, "worker_status", lambda conn: reached.append(1))
    client, _ = _client(app)
    response = client.get("/")
    assert response.status_code == 503
    assert "pg_pass_policy is not preloaded</h1>" in response.text
    assert "<nav>" in response.text
    assert "shared memory is not initialized" in response.text
    assert HINT in response.text
    assert reached == []
    assert "pg_pass_policy is not preloaded (GET /)" in caplog.text


@pytest.mark.parametrize("path", ["/roles", "/profiles", "/pairs"])
def test_every_view_page_gets_the_dedicated_page(app, monkeypatch, path):
    for name in ("list_roles", "list_profiles", "list_pairs"):
        monkeypatch.setattr(db, name, _raise(NotPreloaded()))
    client, _ = _client(app)
    response = client.get(path)
    assert response.status_code == 503 and HINT in response.text


def test_not_preloaded_htmx_is_a_retargeted_alert(app, monkeypatch):
    monkeypatch.setattr(db, "list_roles", _raise(NotPreloaded()))
    client, _ = _client(app)
    response = client.get("/roles/table", headers={"HX-Request": "true"})
    assert response.status_code == 503
    assert response.headers["HX-Retarget"] == "#alerts"
    assert f"(hint: {HINT})" in response.text


def test_not_preloaded_action_is_the_dedicated_page_not_inline(app, monkeypatch):
    monkeypatch.setattr(db, "lock_role", _raise(NotPreloaded()))
    client, token = _client(app)
    response = client.post("/roles/r1/lock", headers={"X-CSRF-Token": token})
    assert response.status_code == 503 and HINT in response.text


def test_other_55000_is_a_generic_500(app, monkeypatch, caplog):
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(db, "list_roles", _raise(NotPreloaded("some other state", None)))
    client, _ = _client(app)
    response = client.get("/roles")
    assert response.status_code == 500
    assert "Database error, see the server log" in response.text
    assert "some other state" not in response.text
    assert "database error on GET /roles: some other state" in caplog.text


# --- 2: only the extension's errors are shown inline -----------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.InsufficientPrivilege("pg_pass_policy: permission denied"),
        psycopg.errors.UndefinedObject('pg_pass_policy: role "x" does not exist'),
        psycopg.errors.CheckViolation('new row violates check constraint "profile_check"'),
        psycopg.errors.InvalidParameterValue("password length must be between 8 and 128"),
        psycopg.errors.InvalidDatetimeFormat('invalid input syntax for type interval: "abc"'),
        psycopg.errors.RaiseException("pg_pass_policy: password generation failed"),
        psycopg.errors.InvalidPassword("PPP-010: password changed too recently"),
        psycopg.errors.ObjectInUse('pg_pass_policy: profile "p" is assigned to 2 role(s)'),
        # the prefix alone is enough, whatever the SQLSTATE but an internal one
        psycopg.errors.FeatureNotSupported("pg_pass_policy: not supported here"),
        psycopg.errors.ObjectNotInPrerequisiteState(
            "PPP-004: pg_pass_policy schema is not trusted"
        ),
    ],
)
def test_extension_errors_are_inline(exc):
    assert db.is_extension_error(exc)
    conn = FakeConn([])
    assert db.run_action(conn, _raise(exc)) == (None, db.error_message(exc))
    assert conn.events == ["savepoint", "rollback"]


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.UndefinedTable('relation "pass_policy.profile" does not exist'),
        psycopg.errors.UndefinedFunction("function pass_policy.lock_role() does not exist"),
        psycopg.OperationalError("server closed the connection unexpectedly"),
        psycopg.errors.InternalError_("cache lookup failed for relation 1234"),
        # an internal error of the extension (XX000) is not a refusal
        psycopg.errors.InternalError_("pg_pass_policy: could not generate random values"),
        NotPreloaded(),
    ],
)
def test_other_errors_propagate(exc):
    assert not db.is_extension_error(exc)
    conn = FakeConn([])
    with pytest.raises(type(exc)):
        db.run_action(conn, _raise(exc))
    assert conn.events == ["savepoint", "rollback"]


def test_unexpected_action_error_is_logged_and_a_500(app, monkeypatch, caplog):
    caplog.set_level(logging.ERROR)
    exc = psycopg.errors.UndefinedTable('relation "pass_policy.role_state" does not exist')
    monkeypatch.setattr(db, "lock_role", _raise(exc))
    client, token = _client(app)
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 500
    assert response.headers["HX-Retarget"] == "#alerts"
    assert "Database error, see the server log" in response.text
    assert "role_state" not in response.text
    assert 'database error on POST /roles/r1/lock: relation "pass_policy.role_state"' in caplog.text
    assert "request rollback" in app.state.pool.events
    assert "commit" not in app.state.pool.events


def test_extension_action_error_is_a_422_fragment(app, monkeypatch):
    exc = psycopg.errors.InsufficientPrivilege(
        'pg_pass_policy: only a superuser can manage privileged role "postgres"'
    )
    monkeypatch.setattr(db, "drop_profile", _raise(exc))
    client, token = _client(app)
    response = client.post("/profiles/p1/delete", headers={"X-CSRF-Token": token})
    assert response.status_code == 422
    assert "only a superuser can manage privileged role" in response.text


# --- 4 / 5: profile_edit: reserved names, one 404 path, one form context --------------


# ("." and "..": removed from the URL by the client before routing)
@pytest.mark.parametrize("name", ["assign", "unassign"])
def test_profile_edit_refuses_reserved_names(app, monkeypatch, name):
    looked_up = []
    monkeypatch.setattr(db, "get_profile", lambda conn, n: looked_up.append(n) or {"name": n})
    client, _ = _client(app)
    response = client.get(f"/profiles/{name}")
    assert response.status_code == 404
    assert "is reserved by the web interface" in response.text
    assert 'id="profile-form"' not in response.text
    assert looked_up == []


def test_profile_edit_unknown_is_the_generic_404(app, monkeypatch):
    monkeypatch.setattr(db, "get_profile", lambda conn, n: None)
    client, _ = _client(app)
    response = client.get("/profiles/ghost")
    assert response.status_code == 404
    assert "<nav>" in response.text and "Profile not found" in response.text
    response = client.get("/profiles/ghost", headers={"HX-Request": "true"})
    assert response.status_code == 404 and response.headers["HX-Retarget"] == "#alerts"


def test_profile_form_context_is_built_once(app, monkeypatch):
    import inspect

    calls = []
    real = profiles._form_response

    def spy(*args, **kwargs):
        calls.append(args[1])
        return real(*args, **kwargs)

    monkeypatch.setattr(profiles, "_form_response", spy)
    monkeypatch.setattr(db, "get_profile", lambda conn, n: {"name": n, "min_length": 9})
    client, _ = _client(app)
    response = client.get("/profiles/p1")
    assert response.status_code == 200 and "Profile p1</h1>" in response.text
    response = client.get("/profiles/new")
    assert response.status_code == 200 and "New profile</h1>" in response.text
    assert calls == [{"name": "p1", "min_length": 9}, None]
    source = inspect.getsource(profiles)
    assert source.count('"fields": db.PROFILE_FIELDS') == 1
    assert '"error.html"' not in source


# --- 6: re-read helper ----------------------------------------------------------------


def test_reread_after_commit_returns_the_warning(caplog):
    caplog.set_level(logging.ERROR)
    conn = FakeConn([])
    log = logging.getLogger("pgpp_web.test")
    assert db.reread_after_commit(conn, lambda c: [1], log, "x", "reload") == ([1], None)
    broken = _raise(psycopg.OperationalError("gone"))
    assert db.reread_after_commit(conn, broken, log, "pair p switched", "reload") == (
        None,
        "reload",
    )
    assert "pair p switched, the re-read failed: gone" in caplog.text
