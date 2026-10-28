"""Unit tests, eleventh review round: audit page clamped to the last page,
duplicate basic users refused, '-infinity' timestamps, assignment form
outside the refreshed block (the CSRF refusals are tested in round 13)."""

from __future__ import annotations

import pytest

from app import db
from app.templating import fmt_ts
from tests.conftest import TEST_HASH, TEST_USER, make_settings
from tests.test_review_round3 import FakePool, _app
from tests.test_review_round3 import _client as _recording_client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)

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
        return db.AuditPage(rows, total)

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
