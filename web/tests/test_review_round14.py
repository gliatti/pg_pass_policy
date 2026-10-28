"""Round 14: exempt roles and expiry_state apart from the status (rows of the
roles table, dashboard), CSS of the greyed statuses."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import create_app
from app.templating import STATIC_DIR
from tests.conftest import TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round3 import FakePool


def _row(name: str, status: str, expiry: str, *, exempt: bool = False, **extra) -> dict:
    row = {
        "role_name": name,
        "profile": "default",
        "status": status,
        "expiry_state": expiry,
        "is_exempt": exempt,
        "must_change": False,
        "password_changed_at": None,
        "expires_at": None,
        "days_left": 12,
        "locked_until": None,
        "locked_by": None,
        "lock_reason": None,
        "failed_count": 0,
    }
    row.update(extra)
    return row


ROWS = [
    _row("r_exempt", "exempt", "grace", exempt=True, must_change=True, days_left=-3),
    _row("r_exempt_locked", "locked", "expired", exempt=True, days_left=-40),
    _row("r_locked_expired", "locked", "expired", must_change=True),
    _row("r_locked_ok", "locked", "ok"),
    _row("r_ok", "ok", "ok"),
    _row("r_expired", "expired", "expired", must_change=True),
]


@pytest.fixture
def table(monkeypatch) -> dict[str, str]:
    """HTML of each role group (<tbody class="role">) of /roles/table."""
    app = create_app(make_settings())
    app.state.pool = FakePool([])
    monkeypatch.setattr(db, "list_roles", lambda conn, **kw: ROWS)
    monkeypatch.setattr(db, "profile_names", lambda conn: [])
    client = TestClient(app)
    client.auth = (TEST_USER, TEST_PASSWORD)
    response = client.get("/roles/table")
    assert response.status_code == 200, response.text
    groups = response.text.split('<tbody class="role">')[1:]
    out = {}
    for group in groups:
        name = re.search(r"<strong>([^<]+)</strong>", group).group(1)
        out[name] = group
    assert sorted(out) == sorted(r["role_name"] for r in ROWS)
    return out


def test_exempt_row_has_no_expire_button_nor_must_change(table):
    html = table["r_exempt"]
    assert 'status-exempt">exempt' in html
    assert "/roles/r_exempt/expire" not in html
    assert "must change" not in html
    # days left not shown, expiry state greyed
    assert "-3" not in html
    assert re.search(r'<small class="expiry muted"[^>]*>password: grace</small>', html)
    # the other actions stay
    assert "/roles/r_exempt/rotate" in html and "/roles/r_exempt/lock" in html


def test_exempt_and_locked_row_is_greyed_too(table):
    html = table["r_exempt_locked"]
    assert 'status-locked">locked' in html
    assert re.search(r'<small class="expiry muted"[^>]*>password: expired</small>', html)
    assert "/expire" not in html
    assert "-40" not in html
    assert "/roles/r_exempt_locked/unlock" in html


def test_locked_row_shows_the_expiry_state_apart(table):
    html = table["r_locked_expired"]
    assert 'status-locked">locked' in html
    assert re.search(r'<small class="expiry expiry-expired"[^>]*>password: expired</small>', html)
    # already expired: no Expire button; must change still shown
    assert "/expire" not in html
    assert "must change" in html
    html = table["r_locked_ok"]
    assert re.search(r'<small class="expiry expiry-ok"[^>]*>password: ok</small>', html)
    assert "/roles/r_locked_ok/expire" in html
    assert ">12<" in html


def test_expiry_state_not_repeated_when_equal_to_the_status(table):
    assert "password:" not in table["r_ok"]
    assert "/roles/r_ok/expire" in table["r_ok"]
    assert "password:" not in table["r_expired"]
    assert "/expire" not in table["r_expired"]


def test_dashboard_expiring_list_shows_the_expiry_state(monkeypatch):
    app = create_app(make_settings())
    app.state.pool = FakePool([])
    counts = dict.fromkeys(db.STATUSES, 0) | {"exempt": 2, "locked": 1}
    monkeypatch.setattr(db, "status_counts", lambda conn: counts)
    monkeypatch.setattr(db, "worker_status", lambda conn: None)
    monkeypatch.setattr(db, "recent_audit", lambda conn, limit: [])
    monkeypatch.setattr(
        db,
        "expiring_roles",
        lambda conn: [
            {
                "role_name": "r_lx",
                "status": "locked",
                "expiry_state": "expired",
                "expires_at": None,
                "days_left": -2,
            }
        ],
    )
    client = TestClient(app)
    client.auth = (TEST_USER, TEST_PASSWORD)
    body = client.get("/").text
    assert re.search(r'class="tile status-exempt"[^>]*>\s*<span class="tile-value">2</span>', body)
    assert 'status-locked">locked' in body
    assert 'class="expiry expiry-expired">expired' in body


def test_css_groups_the_greyed_statuses():
    css = (STATIC_DIR / "app.css").read_text()
    assert ".badge.status-exempt" not in css, "the default .badge background is already muted"
    assert re.search(
        r"^\.tile\.status-exempt, \.tile\.status-never_expires, \.tile\.status-unknown "
        r"\{ border-left-color: var\(--muted\); \}$",
        css,
        re.M,
    )
    assert css.count(".tile.status-exempt") == 1
    assert re.search(r"^\.badge \{[^}]*background:var\(--muted\)", css, re.M)


def test_role_queries_read_the_expiry_columns():
    assert "v.is_exempt, v.expiry_state" in db._ROLE_SELECT
    assert "exempt" in db.STATUSES
