"""Unit tests, eleventh review round: CSRF refusal without a session cookie
(no reload loop), audit page clamped to the last page, duplicate basic users
refused, '-infinity' timestamps, one alert helper, assignment form outside
the refreshed block."""

from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.routers import audit, maintenance, profiles
from app.templating import fmt_ts
from tests.conftest import TEST_HASH, TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round3 import FakePool, _app
from tests.test_review_round3 import _client as _recording_client
from tests.test_review_round6 import _client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)

# --- W1: no session cookie: an alert, not a reload loop ----------------------------------


@pytest.mark.parametrize("htmx", [False, True])
def test_a_csrf_refusal_without_session_cookie_does_not_reload(app, htmx):  # noqa: F811
    # a client that never got the session cookie and sends no token
    client = TestClient(app, follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    headers = {"HX-Request": "true"} if htmx else {}
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers
    assert "CSRF token missing: fetch a page first" in response.text
    assert "Session cookie not stored" in response.text
    assert "PGPP_WEB_SESSION_HTTPS_ONLY" in response.text
    if htmx:
        assert response.headers["HX-Retarget"] == "#alerts"


def test_a_secure_cookie_over_plain_http_is_reported():
    """PGPP_WEB_SESSION_HTTPS_ONLY behind plain HTTP: the client drops the
    Secure cookie, every action is refused; the alert says why instead of
    asking htmx to reload (which would loop)."""
    app = main.create_app(make_settings(session_https_only=True))
    app.state.pool = FakePool([])
    client = TestClient(app, base_url="http://testserver", follow_redirects=False)
    client.auth = (TEST_USER, TEST_PASSWORD)
    page = client.get("/maintenance")
    assert "__Host-pgpp_session" in page.headers.get("set-cookie", "")
    # kept in the jar, but never sent back over http:// (Secure)
    headers = {"X-CSRF-Token": "x", "HX-Request": "true", "Origin": "http://testserver"}
    response = client.post("/maintenance/run", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers
    assert "Session cookie not stored" in response.text


def test_a_stale_token_with_a_session_cookie_still_reloads(app):  # noqa: F811
    client, _ = _client(app)
    assert "pgpp_session" in client.cookies
    response = client.post(
        "/roles/r1/lock", headers={"X-CSRF-Token": "stale", "HX-Request": "true"}
    )
    assert response.status_code == 403
    assert response.headers["HX-Refresh"] == "true"
    assert "Session cookie not stored" not in response.text


# --- W2: a page past the end shows the last page -----------------------------------------


@pytest.mark.parametrize(
    ("total", "requested", "shown", "offsets"),
    [
        (120, 7, 3, [300, 100]),  # page_size 50: 3 pages
        (120, 3, 3, [100]),
        (0, 5, 1, [200]),  # nothing matches: no second query
        (0, 1, 1, [0]),
    ],
)
def test_the_audit_page_is_clamped(monkeypatch, total, requested, shown, offsets):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        seen.append(offset)
        rows = [] if offset >= total else [{"id": 1, "event_type": "auth_failed"}]
        return rows, total

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _recording_client(app, events)
    response = client.get("/audit/table", params={"page": str(requested)})
    assert response.status_code == 200
    assert seen == offsets
    pages = max(1, -(-total // 50))
    assert f"page {shown} / {pages}" in response.text


# --- W3: a user listed twice is refused at startup ---------------------------------------


def test_duplicate_basic_users_are_refused():
    users = f"{TEST_USER}:{TEST_HASH},other:{TEST_HASH}, {TEST_USER}:{TEST_HASH}"
    with pytest.raises(ValueError, match="'admin' is listed more than once"):
        make_settings(basic_users=users)
    # distinct users are fine
    make_settings(basic_users=f"{TEST_USER}:{TEST_HASH},other:{TEST_HASH}")


# --- W4: '-infinity' -----------------------------------------------------------------------


def test_minus_infinity_is_rendered():
    assert fmt_ts("-infinity") == "−∞"
    assert fmt_ts("infinity") == "∞ (manual)"
    loader = db.InfinityTimestamptzLoader(0)
    assert loader.load(b"-infinity") == "-infinity"
    assert loader.load(b"infinity") == "infinity"


# --- W6 / W7: one alert helper, no dead branch -------------------------------------------


def test_the_alert_fragment_is_built_by_one_helper():
    for module in (main, profiles, maintenance, audit):
        source = inspect.getsource(module)
        assert '"_alert.html"' not in source, module.__name__
    assert '"session" not in request.scope' not in inspect.getsource(main)


# --- W8: assign / unassign do not recompute the role list --------------------------------


@pytest.mark.parametrize(
    ("path", "data"),
    [("/profiles/assign", {"role": "r1", "profile": "p1"}), ("/profiles/unassign", {"role": "r1"})],
)
def test_assignment_fragments_skip_login_roles(monkeypatch, path, data):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    app.state.session_superuser = False
    monkeypatch.setattr(db, "assignments", lambda conn: [])
    monkeypatch.setattr(
        db, "login_roles", lambda *a: pytest.fail("login_roles() called by a fragment")
    )
    monkeypatch.setattr(db, "assign_profile", lambda conn, role, profile: None)
    monkeypatch.setattr(db, "unassign_profile", lambda conn, role: None)
    client, token = _recording_client(app, events)
    response = client.post(path, data=data, headers={"X-CSRF-Token": token, "HX-Request": "true"})
    assert response.status_code == 200, response.text
    assert "<select" not in response.text
