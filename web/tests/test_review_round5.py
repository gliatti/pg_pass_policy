"""Unit tests, fifth review round: application_name kept ASCII and within
63 bytes, empty name in the new profile form, shared savepoint-and-commit
helper, single assignments context, audit filters built once."""

from __future__ import annotations

import re

import psycopg
import pytest

from app import db
from app.routers import profiles
from tests.test_review_round3 import FakePool, _app, _client

# --- 3: application_name --------------------------------------------------------------


def test_application_name_ascii_user_is_unchanged():
    assert db.application_name("pgpp-web", "alice") == "pgpp-web:alice"
    assert db.application_name("pgpp-web", None) == "pgpp-web:anonymous"


def test_application_name_non_ascii_is_percent_encoded():
    name = db.application_name("pgpp-web", "Émilie")
    assert name == "pgpp-web:%C3%89milie"
    assert name.isascii()
    # '%' itself is encoded: the value decodes back without ambiguity
    assert db.application_name("pgpp-web", "a%b") == "pgpp-web:a%25b"


@pytest.mark.parametrize("user", ["Émilie" * 20, "日本語のユーザー名" * 5, "x" * 100])
def test_application_name_is_bounded_in_bytes(user):
    name = db.application_name("pgpp-web", user)
    assert name.isascii()
    assert len(name.encode()) <= db.APPLICATION_NAME_MAX
    assert name.startswith("pgpp-web:")
    # never cut inside an escape sequence: the value is a valid UTF-8 prefix
    from urllib.parse import unquote_to_bytes

    raw = unquote_to_bytes(name)
    raw.decode("utf-8")  # raises on a split multibyte character
    assert re.search(r"%[0-9A-F]?$", name) is None


def test_set_actor_sends_the_bounded_name():
    class Conn:
        def execute(self, sql, params):
            self.params = params

    conn = Conn()
    db.set_actor(conn, type("S", (), {"app_name": "pgpp-web"})(), "Émilie")
    assert conn.params == ("pgpp-web:%C3%89milie",)


# --- 4: the new profile form starts with an empty name ------------------------------------


def test_new_profile_form_has_an_empty_name(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    defaults = {k: 7 for k, kind in db.PROFILE_FIELDS if kind == "int"}
    monkeypatch.setattr(db, "get_profile", lambda conn, name: {"name": "default", **defaults})
    client, _ = _client(app, events)
    response = client.get("/profiles/new")
    assert response.status_code == 200
    assert 'name="name" value=""' in response.text
    assert 'value="default"' not in response.text
    assert 'name="min_length" value="7"' in response.text


# --- 6: one savepoint-and-commit helper for every action ----------------------------------


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


def test_run_action_commits_on_success_only():
    conn = _Conn()
    assert db.run_action(conn, lambda c, a, b: a + b, 1, 2) == (3, None)
    assert conn.commits == 1

    def fail(c):
        raise psycopg.errors.InsufficientPrivilege("refused")

    assert db.run_action(conn, fail) == (None, "refused")
    assert conn.commits == 1


def test_no_router_reimplements_the_savepoint_and_commit():
    import inspect

    from app.routers import maintenance, pairs, roles

    for module in (roles, pairs, profiles, maintenance):
        source = inspect.getsource(module)
        assert ".commit()" not in source, module.__name__
        assert "conn.transaction()" not in source, module.__name__
        assert not hasattr(module, "_run") and not hasattr(module, "_commit")


@pytest.mark.parametrize(
    ("path", "patch", "data"),
    [
        (
            "/pairs",
            "create_pair",
            {"pair_name": "p", "role_a": "a", "role_b": "b", "group_role": "g"},
        ),
        ("/profiles/unassign", "unassign_profile", {"role": "r"}),
        ("/profiles/p/p1", "alter_profile", None),
    ],
)
def test_more_write_actions_commit_before_response(monkeypatch, path, patch, data):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    app.state.session_superuser = True
    monkeypatch.setattr(db, patch, lambda conn, *a, **k: events.append("action"))
    for name in ("assignments", "login_roles", "profile_names", "list_pairs"):
        monkeypatch.setattr(db, name, lambda *a: [])
    monkeypatch.setattr(db, "get_profile", lambda conn, name: {"name": name})
    monkeypatch.setattr(profiles, "settings_from_form", lambda form: {})
    client, token = _client(app, events)
    response = client.post(path, data=data or {}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200, response.text
    assert events[:2] == ["action", "commit"]
    assert events[-1].startswith("response")


# --- 7: one context for the assignments block ---------------------------------------------


def test_assignments_fragment_and_page_share_the_context(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    app.state.session_superuser = False
    calls: list[str] = []
    monkeypatch.setattr(db, "assignments", lambda conn: calls.append("assignments") or [])
    monkeypatch.setattr(
        db, "login_roles", lambda conn, su: calls.append(f"login_roles {su}") or ["r1"]
    )
    monkeypatch.setattr(db, "profile_names", lambda conn: calls.append("names") or ["default"])
    monkeypatch.setattr(db, "list_profiles", lambda conn: calls.append("profiles") or [])
    monkeypatch.setattr(db, "unassign_profile", lambda conn, role: None)
    client, token = _client(app, events)

    page = client.get("/profiles")
    assert page.status_code == 200
    # the page derives the names from the profiles: no profile_names() query
    assert calls == ["profiles", "assignments", "login_roles False"]
    # the form is outside the block that assign / unassign replace
    form = page.text.index('<form class="inline" hx-post="/profiles/assign"')
    assert '<option value="r1">' in page.text
    assert form < page.text.index('<div id="assignments">')
    calls.clear()
    response = client.post(
        "/profiles/unassign", data={"role": "r1"}, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 200
    # the fragment is the alert and the table only: the form (and its
    # login_roles() query) stays outside the refreshed block
    assert calls == ["assignments"]
    assert "<select" not in response.text
    assert "r1 is back on the default profile" in response.text


# --- 8: audit pager links built from one query string -------------------------------------


def test_audit_pager_links_carry_the_filters(monkeypatch):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    monkeypatch.setattr(db, "list_audit", lambda conn, **kw: db.AuditPage([], 500))
    client, _ = _client(app, events)
    response = client.get(
        "/audit/table", params={"role": "a b&c", "type": "auth_failed", "page": "2"}
    )
    assert response.status_code == 200
    qs = "?role=a%20b%26c&amp;type=auth_failed&amp;since="
    assert f'hx-get="/audit/table{qs}&page=1"' in response.text
    assert f'href="/audit{qs}&page=1"' in response.text
    assert f'hx-get="/audit/table{qs}&page=3"' in response.text
    assert f'href="/audit{qs}&page=3"' in response.text
