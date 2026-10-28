"""Unit tests, thirteenth review round: the CSRF refusals (stale token,
no token, with or without the session cookie, htmx or not), the 404 of the
routes of a "." / ".." profile (delete included), no edit link nor delete
form for such a profile in the listing."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.csrf import TOKEN_MISSING
from app.routers import profiles
from tests.conftest import TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round3 import FakePool
from tests.test_review_round6 import _client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)


def _secure_app():
    app = main.create_app(make_settings(session_https_only=True))
    app.state.pool = FakePool([])
    return app


def _csrf_client(app, setup: str) -> tuple[TestClient, str, dict[str, str], bool]:
    """(client, URL, extra headers, whether the session cookie is sent) of a
    client that loaded a page or not, over plain HTTP or HTTPS."""
    if setup == "page loaded":
        client, _ = _client(app)
        return client, "/roles/r1/lock", {}, True
    if setup == "no page loaded":
        client = TestClient(app, follow_redirects=False)
        client.auth = (TEST_USER, TEST_PASSWORD)
        return client, "/roles/r1/lock", {}, False
    https = setup == "Secure cookie over https"
    base = "https://testserver" if https else "http://testserver"
    client = TestClient(_secure_app(), base_url=base, follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    page = client.get("/maintenance")
    assert "__Host-pgpp_session" in page.headers.get("set-cookie", "")
    # over http:// the Secure cookie stays in the jar but is never sent back
    return client, "/maintenance/run", {"Origin": base}, https


# --- the CSRF refusals ------------------------------------------------------------------


@pytest.mark.parametrize(
    "setup",
    ["page loaded", "no page loaded", "Secure cookie over https", "Secure cookie over http"],
)
@pytest.mark.parametrize("supplied", [True, False])
@pytest.mark.parametrize("htmx", [False, True])
def test_csrf_refusals(app, setup, supplied, htmx):  # noqa: F811
    """A token supplied (taken from a page, no longer valid): htmx reloads
    the page (HX-Refresh), a plain form gets "reload the page", completed by
    the cookie alert when no session cookie came with it.  No token at all
    (the client loaded no page): TOKEN_MISSING alone, never the cookie
    alert."""
    client, url, headers, cookie_sent = _csrf_client(app, setup)
    if supplied:
        headers["X-CSRF-Token"] = "stale"
    if htmx:
        headers["HX-Request"] = "true"
    response = client.post(url, headers=headers)
    assert response.status_code == 403
    if htmx:
        assert response.headers["HX-Retarget"] == "#alerts"
    if supplied and htmx:
        assert response.headers["HX-Refresh"] == "true"
    else:
        assert "HX-Refresh" not in response.headers
    if supplied:
        assert "CSRF token invalid: reload the page" in response.text
    else:
        assert TOKEN_MISSING in response.text
    alert = supplied and not htmx and not cookie_sent
    assert ("Session cookie not stored" in response.text) is alert
    if alert:
        assert "CSRF token invalid: reload the page. Session cookie not stored" in response.text
        assert "PGPP_WEB_SESSION_HTTPS_ONLY" in response.text


# --- 3: the 404 of the routes of a reserved profile ----------------------------------------


@pytest.mark.parametrize("encoded", ["%2E", "%2E%2E"])
@pytest.mark.parametrize("method", ["get", "post"])
def test_reserved_profile_routes_say_sql_only(app, monkeypatch, encoded, method):  # noqa: F811
    """GET (edit page) and POST (update) of /profiles/p/%2E and %2E%2E: one
    guard, the same 404 before any query."""
    monkeypatch.setattr(db, "get_profile", lambda *a: pytest.fail("get_profile called"))
    monkeypatch.setattr(db, "alter_profile", lambda *a: pytest.fail("alter_profile called"))
    client, token = _client(app)
    kwargs = {"headers": {"X-CSRF-Token": token}, "data": {}} if method == "post" else {}
    response = getattr(client, method)(f"/profiles/p/{encoded}", **kwargs)
    assert response.status_code == 404
    name = "." if encoded == "%2E" else ".."
    # autoescaped quotes
    assert f"profile &#34;{name}&#34; cannot be managed from this interface" in response.text
    assert "is reserved by the web interface" not in response.text
    assert 'id="profile-form"' not in response.text
    assert profiles.RESERVED_NAMES == {".", ".."}
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
