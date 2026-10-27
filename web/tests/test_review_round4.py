"""Unit tests, fourth review round: joins by OID, synchronous form
endpoints, privileged targets left to the extension, profile filter queried
for the full roles page only, 404 of an unknown profile update, shared error
helper, dummy hash of the configured bcrypt cost."""

from __future__ import annotations

import base64
import inspect

import bcrypt
import psycopg
import pytest

from app import auth, db
from app.config import bcrypt_cost
from app.routers import profiles, roles
from tests.conftest import make_settings
from tests.test_review_round3 import FakePool, _app, _client

# --- 1 / 3: role_state and role_profile are joined by OID --------------------------------


def test_role_select_joins_role_state_by_oid():
    assert "s.role_oid = v.role_oid" in db._ROLE_SELECT
    assert "s.role_name = v.role_name" not in db._ROLE_SELECT


def test_assignments_show_the_current_role_name():
    sql = db._ASSIGNMENTS_SQL
    assert "pg_catalog.pg_roles r ON r.oid = rp.role_oid" in sql
    assert "coalesce(r.rolname::text, rp.role_name) AS role_name" in sql


# --- 2: no blocking psycopg call in a coroutine ------------------------------------------


@pytest.mark.parametrize("endpoint", [profiles.profile_create, profiles.profile_update])
def test_profile_form_endpoints_are_not_coroutines(endpoint):
    assert not inspect.iscoroutinefunction(endpoint)


def test_no_router_endpoint_is_a_coroutine():
    # every endpoint takes a psycopg connection: all must run in the thread pool
    app = _app()
    for route in app.routes:
        module = getattr(getattr(route, "endpoint", None), "__module__", "")
        if module.startswith("app.routers."):
            assert not inspect.iscoroutinefunction(route.endpoint), route.path


def test_profile_create_still_reads_the_form(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    created = {}
    monkeypatch.setattr(db, "create_profile", lambda conn, name, s: created.update(s, name=name))
    client, token = _client(app, events)
    data = {k: "1" for k, kind in db.PROFILE_FIELDS if kind == "int"}
    data |= {k: "1 day" for k, kind in db.PROFILE_FIELDS if kind.startswith("interval")}
    data |= {"name": "p1", "reject_username": "on"}
    response = client.post("/profiles", data=data, headers={"X-CSRF-Token": token})
    assert response.status_code == 303, response.text
    assert created["name"] == "p1" and created["min_length"] == 1
    assert created["reject_username"] is True and created["reject_dictionary"] is False


# --- 4: a forged privileged target is refused by the extension ----------------------------

EXT_MESSAGE = 'pg_pass_policy: only a superuser can manage privileged role "postgres"'


@pytest.mark.parametrize(
    ("path", "action"),
    [("/profiles/assign", "assign_profile"), ("/profiles/unassign", "unassign_profile")],
)
def test_privileged_target_error_comes_from_the_extension(monkeypatch, path, action):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    app.state.session_superuser = False
    assert not hasattr(db, "privileged_target_refused")

    def refuse(conn, *args):
        events.append("action")
        raise psycopg.errors.InsufficientPrivilege(EXT_MESSAGE)

    monkeypatch.setattr(db, action, refuse)
    for name in ("assignments", "login_roles", "profile_names"):
        monkeypatch.setattr(db, name, lambda *a: [])
    client, token = _client(app, events)
    response = client.post(
        path,
        data={"role": "postgres", "profile": "p"},
        headers={"X-CSRF-Token": token, "HX-Request": "true"},
    )
    assert response.status_code == 422
    assert "only a superuser can manage privileged role &#34;postgres&#34;" in response.text
    assert events[0] == "action"


# --- 5: the roles table fragment does not query the profile names -------------------------


def test_profile_names_only_for_the_full_roles_page(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    calls = []
    monkeypatch.setattr(db, "list_roles", lambda conn, **kw: [])
    monkeypatch.setattr(db, "profile_names", lambda conn: calls.append(1) or ["default"])
    client, _ = _client(app, events)
    response = client.get("/roles/table", headers={"HX-Request": "true"})
    assert response.status_code == 200 and calls == []
    response = client.get("/roles")
    assert response.status_code == 200 and calls == [1]
    assert '<option value="default">' in response.text
    assert "profiles" not in roles._table_context(None, roles._filters(None, None, None))


# --- 6: update of an unknown profile ------------------------------------------------------


def test_update_of_an_unknown_profile_is_a_retargeted_404(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    monkeypatch.setattr(db, "get_profile", lambda conn, name: None)
    monkeypatch.setattr(db, "alter_profile", lambda *a: events.append("alter"))
    client, token = _client(app, events)
    response = client.post(
        "/profiles/ghost", data={}, headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 404
    assert response.headers["HX-Retarget"] == "#alerts"
    assert "Profile not found" in response.text
    assert "alter" not in events

    response = client.post("/profiles/ghost", data={"csrf_token": token})
    assert response.status_code == 404
    assert "<nav>" in response.text and "Profile not found" in response.text


# --- 7: shared helpers --------------------------------------------------------------------


def test_error_message_accepts_any_exception():
    assert db.error_message(ValueError("every field is required")) == "every field is required"
    assert db.error_message(psycopg.errors.RaiseException("PPP-010 too recent")).startswith(
        "PPP-010"
    )


class _Tx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Conn:
    def __init__(self):
        self.commits = 0

    def transaction(self):
        return _Tx()

    def commit(self):
        self.commits += 1


def test_run_returns_the_result_or_the_error():
    conn = _Conn()
    assert roles._run(conn, lambda c, x: x * 2, 21) == (42, None)
    assert conn.commits == 1

    def fail(c):
        raise psycopg.errors.InsufficientPrivilege("refused")

    assert roles._run(conn, fail) == (None, "refused")
    assert conn.commits == 1


# --- 8: dummy hash of the configured cost -------------------------------------------------


def _hash(password: bytes, cost: int) -> str:
    return bcrypt.hashpw(password, bcrypt.gensalt(rounds=cost)).decode()


def test_bcrypt_cost():
    assert bcrypt_cost(b"$2b$05$" + b"x" * 53) == 5
    assert bcrypt_cost(b"$2a$31$") == 31
    assert bcrypt_cost(b"$2b$03$") is None
    assert bcrypt_cost(b"$2b$xx$") is None


def test_dummy_hash_has_the_configured_cost(monkeypatch):
    settings = make_settings(basic_users=f"alice:{_hash(b'alice-password-1', 5)}")
    users = settings.basic_user_hashes()
    assert bcrypt_cost(auth.dummy_hash(users)) == 5
    seen = []
    real = bcrypt.checkpw
    monkeypatch.setattr(bcrypt, "checkpw", lambda pw, h: seen.append(h) or real(pw, h))
    header = "Basic " + base64.b64encode(b"ghost:whatever").decode()
    assert auth.verify_basic(header, users) is None
    assert seen == [auth.dummy_hash(users)]
    assert bcrypt_cost(seen[0]) == 5


def test_mixed_bcrypt_costs_are_refused():
    users = f"alice:{_hash(b'a', 4)},bob:{_hash(b'b', 5)}"
    with pytest.raises(ValueError, match="same cost"):
        make_settings(basic_users=users)


def test_unreadable_bcrypt_cost_is_refused():
    with pytest.raises(ValueError, match="unreadable bcrypt cost"):
        make_settings(basic_users="alice:$2b$xx$" + "x" * 53)
