"""Unit tests, twelfth review round: the three CSRF refusals (stale token,
no token, Secure cookie over HTTP), audit pagination without a useless
second query, one reserved-name guard for the profile routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.routers import profiles
from tests.conftest import TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round3 import FakePool, _app
from tests.test_review_round3 import _client as _recording_client
from tests.test_review_round6 import _client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)

# --- 1: CSRF refusals ----------------------------------------------------------------------


def test_a_stale_token_without_session_cookie_reloads(app):  # noqa: F811
    """The session cookie expired (max_age) while the page stayed open: the
    page still sends its token, htmx reloads it for a fresh one."""
    client = TestClient(app, follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    response = client.post(
        "/roles/r1/lock", headers={"X-CSRF-Token": "from-a-page", "HX-Request": "true"}
    )
    assert response.status_code == 403
    assert response.headers["HX-Refresh"] == "true"
    assert "CSRF token invalid: reload the page" in response.text
    assert "Session cookie not stored" not in response.text


@pytest.mark.parametrize("htmx", [False, True])
def test_no_token_with_a_session_cookie(app, htmx):  # noqa: F811
    client, _ = _client(app)
    assert "pgpp_session" in client.cookies
    headers = {"HX-Request": "true"} if htmx else {}
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers
    assert "CSRF token missing: fetch a page first" in response.text
    assert "Session cookie not stored" not in response.text


def test_a_secure_cookie_over_https_reloads():
    app = main.create_app(make_settings(session_https_only=True))
    app.state.pool = FakePool([])
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    headers = {"X-CSRF-Token": "stale", "HX-Request": "true", "Origin": "https://testserver"}
    response = client.post("/maintenance/run", headers=headers)
    assert response.status_code == 403
    assert response.headers["HX-Refresh"] == "true"


# --- 2 / 3: one audit query when nothing matches -------------------------------------------


@pytest.mark.parametrize(("requested", "offsets"), [(5, [200]), (1, [0])])
def test_an_empty_audit_is_queried_once(monkeypatch, requested, offsets):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        seen.append(offset)
        return [], 0

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _recording_client(app, events)
    response = client.get("/audit/table", params={"page": str(requested)})
    assert response.status_code == 200
    assert seen == offsets
    assert "page 1 / 1" in response.text


# --- 5: one reserved-name guard ------------------------------------------------------------


@pytest.mark.parametrize("encoded", ["%2E", "%2E%2E"])
@pytest.mark.parametrize("method", ["get", "post"])
def test_reserved_names_share_one_guard(app, monkeypatch, encoded, method):  # noqa: F811
    looked_up: list[str] = []
    monkeypatch.setattr(db, "get_profile", lambda conn, n: looked_up.append(n) or {"name": n})
    monkeypatch.setattr(db, "alter_profile", lambda *a: pytest.fail("alter_profile called"))
    client, token = _client(app)
    kwargs = {"headers": {"X-CSRF-Token": token}, "data": {}} if method == "post" else {}
    response = getattr(client, method)(f"/profiles/p/{encoded}", **kwargs)
    assert response.status_code == 404
    assert "is managed in SQL only" in response.text
    assert looked_up == []
    assert profiles.RESERVED_NAMES == {".", ".."}
