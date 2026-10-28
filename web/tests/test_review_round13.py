"""Unit tests, thirteenth review round: the Secure-cookie-over-HTTP alert
only without a session cookie, its message composed with the CSRF
refusal, the 404 of the routes of a "." / ".." profile (delete included),
no edit link nor delete form for such a profile in the listing."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.routers import profiles
from tests.conftest import TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round3 import FakePool
from tests.test_review_round6 import _client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)


def _secure_app():
    app = main.create_app(make_settings(session_https_only=True))
    app.state.pool = FakePool([])
    return app


def _https_client_with_cookie(app) -> TestClient:
    """A client that got the Secure session cookie (page loaded over HTTPS)."""
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    client.get("/maintenance")
    assert "__Host-pgpp_session" in client.cookies
    return client


# --- 1: a stale token with the session cookie present always reloads ------------------------


def test_a_stale_token_with_the_cookie_reloads_despite_an_http_origin():
    """Origin in http:// (a proxy rewriting the scheme, a mixed setup) but the
    cookie did arrive: the token is merely stale, htmx reloads the page."""
    client = _https_client_with_cookie(_secure_app())
    headers = {"X-CSRF-Token": "stale", "HX-Request": "true", "Origin": "http://testserver"}
    response = client.post("/maintenance/run", headers=headers)
    assert response.status_code == 403
    assert response.headers["HX-Refresh"] == "true"
    assert "CSRF token invalid: reload the page" in response.text
    assert "Session cookie not stored" not in response.text


def test_a_stale_token_without_the_cookie_over_http_is_reported():
    client = TestClient(_secure_app(), base_url="http://testserver", follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    headers = {"X-CSRF-Token": "stale", "HX-Request": "true", "Origin": "http://testserver"}
    response = client.post("/maintenance/run", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers
    assert "Session cookie not stored" in response.text


# --- 5: the CSRF refusal kept, completed by the cookie alert -------------------------------


@pytest.mark.parametrize("htmx", [False, True])
def test_the_csrf_message_is_kept_with_the_cookie_alert(htmx):
    client = TestClient(_secure_app(), base_url="http://testserver", follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    headers = {"X-CSRF-Token": "stale", "Origin": "http://testserver"}
    if htmx:
        headers["HX-Request"] = "true"
    response = client.post("/maintenance/run", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers
    assert "CSRF token invalid: reload the page. Session cookie not stored" in response.text


# --- 3: the 404 of the routes of a reserved profile ----------------------------------------


@pytest.mark.parametrize("encoded", ["%2E", "%2E%2E"])
@pytest.mark.parametrize("method", ["get", "post"])
def test_reserved_profile_routes_say_sql_only(app, monkeypatch, encoded, method):  # noqa: F811
    monkeypatch.setattr(db, "get_profile", lambda *a: pytest.fail("get_profile called"))
    client, token = _client(app)
    kwargs = {"headers": {"X-CSRF-Token": token}, "data": {}} if method == "post" else {}
    response = getattr(client, method)(f"/profiles/p/{encoded}", **kwargs)
    assert response.status_code == 404
    name = "." if encoded == "%2E" else ".."
    # autoescaped quotes
    assert f"profile &#34;{name}&#34; cannot be managed from this interface" in response.text
    assert "is reserved by the web interface" not in response.text
    assert profiles.SQL_ONLY_MESSAGE != profiles.RESERVED_MESSAGE


@pytest.mark.parametrize("encoded", ["%2E", "%2E%2E"])
@pytest.mark.parametrize("htmx", [False, True])
def test_reserved_profile_delete_is_refused_before_any_query(
    app,  # noqa: F811
    monkeypatch,
    encoded,
    htmx,
):
    """POST /profiles/p/%2E/delete: the same 404 as the edit page and the
    update, before drop_profile() (a profile "." created with SQL is not
    dropped from the web interface)."""
    monkeypatch.setattr(db, "drop_profile", lambda *a: pytest.fail("drop_profile called"))
    monkeypatch.setattr(db, "run_action", lambda *a: pytest.fail("run_action called"))
    client, token = _client(app)
    headers = {"X-CSRF-Token": token}
    if htmx:
        headers["HX-Request"] = "true"
    response = client.post(f"/profiles/p/{encoded}/delete", headers=headers)
    assert response.status_code == 404
    name = "." if encoded == "%2E" else ".."
    assert f"profile &#34;{name}&#34; cannot be managed from this interface" in response.text
    # does not claim that the profile exists
    assert "exist" not in response.text.lower()
    if htmx:
        assert response.headers["HX-Retarget"] == "#alerts"


# --- 4: no edit link nor delete form for "." / ".." ----------------------------------------


def test_reserved_profiles_are_listed_without_actions(app, monkeypatch):  # noqa: F811
    rows = [{"name": n, "assigned_roles": 0} for n in (".", "..", "p1")]
    monkeypatch.setattr(db, "list_profiles", lambda conn: rows)
    monkeypatch.setattr(db, "assignments", lambda conn: [])
    monkeypatch.setattr(db, "login_roles", lambda conn, superuser: [])
    monkeypatch.setattr(db, "session_is_superuser", lambda request, conn: False)
    client, _ = _client(app)
    response = client.get("/profiles")
    assert response.status_code == 200, response.text
    page = response.text
    assert 'href="/profiles/p/p1"' in page
    assert 'action="/profiles/p/p1/delete"' in page
    for name in (".", ".."):
        assert f'href="/profiles/p/{name}"' not in page
        assert f'action="/profiles/p/{name}/delete"' not in page
        assert f"Delete profile {name}?" not in page
    assert page.count("(SQL only)") == 2
