"""Unit tests, tenth review round: "not installed" detected by SQLSTATE only
(translated messages), pool connections checked, CSRF refusal reloading an
htmx page, truncated bcrypt hashes refused at startup, NULL pair password,
timestamps with their offset, profile delete without JavaScript, CSRF token
only in hx-headers."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta, timezone

import psycopg
import pytest

from app import db
from app.routers import pairs
from app.templating import fmt_ts
from tests.conftest import CSRF_HX_HEADERS, TEST_HASH, make_settings
from tests.test_review_round6 import _client, _raise
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)
from tests.test_review_round9 import _ExtConn

# --- W1: SQLSTATE only, never the (translated) text -------------------------------------

FR_MISSING_SCHEMA = "le schéma « pass_policy » n'existe pas"
FR_MISSING_VIEW = "la relation « pass_policy.v_role_status » n'existe pas"


def test_a_translated_missing_schema_is_not_installed():
    found = db.extension_unavailable(psycopg.errors.InvalidSchemaName(FR_MISSING_SCHEMA))
    assert found is not None and found.reason == "not_installed"
    assert found.message == FR_MISSING_SCHEMA


@pytest.mark.parametrize("installed", [False, True])
def test_a_translated_missing_relation_is_checked_against_pg_extension(installed):
    conn = _ExtConn([], installed)
    found = db.missing_extension_error(conn, psycopg.errors.UndefinedTable(FR_MISSING_VIEW))
    assert "pg_extension" in conn.queries[0]
    if installed:
        assert found is None
    else:
        assert db.extension_unavailable(found).reason == "not_installed"


# --- W2: connections checked when they leave the pool ------------------------------------


def test_pool_checks_its_connections(monkeypatch):
    seen = {}

    class Pool:
        check_connection = staticmethod(lambda conn: None)

        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(db, "ConnectionPool", Pool)
    db.make_pool(make_settings())
    assert seen["check"] is Pool.check_connection
    assert seen["open"] is False


# --- W3: a refused CSRF token reloads an htmx page ---------------------------------------


@pytest.mark.parametrize("htmx", [False, True])
def test_a_stale_csrf_token_asks_htmx_to_reload(app, htmx):  # noqa: F811
    client, _ = _client(app)
    headers = {"X-CSRF-Token": "stale"}
    if htmx:
        headers["HX-Request"] = "true"
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 403
    assert "reload the page" in response.text
    if htmx:
        assert response.headers["HX-Refresh"] == "true"
        assert response.headers["HX-Retarget"] == "#alerts"
    else:
        assert "HX-Refresh" not in response.headers


def test_a_cross_site_request_does_not_reload(app):  # noqa: F811
    client, token = _client(app)
    headers = {"X-CSRF-Token": token, "HX-Request": "true", "Sec-Fetch-Site": "cross-site"}
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 403
    assert "HX-Refresh" not in response.headers


# --- W4: a truncated or mangled bcrypt hash is refused at startup ------------------------


@pytest.mark.parametrize(
    "digest",
    [
        TEST_HASH[:-1],  # truncated
        TEST_HASH[:30],
        TEST_HASH + "x",  # too long
        TEST_HASH[:-1] + "!",  # outside bcrypt's alphabet
        TEST_HASH[:-1] + "é",
    ],
)
def test_a_malformed_bcrypt_hash_is_refused(digest):
    with pytest.raises(ValueError, match="truncated or malformed"):
        make_settings(basic_users=f"alice:{digest}")


def test_a_whole_bcrypt_hash_is_accepted():
    assert len(TEST_HASH) == 60
    users = make_settings(basic_users=f"alice:{TEST_HASH}").basic_user_hashes()
    assert users == {"alice": TEST_HASH.encode()}


# --- W5: a pair switch returning a NULL password -----------------------------------------


@pytest.mark.parametrize("password", [None, ""])
def test_switch_with_a_null_password_is_a_warning(app, monkeypatch, caplog, password):  # noqa: F811
    caplog.set_level(logging.ERROR)
    row = {
        "active_role": "a",
        "password": password,
        "previous_role": "b",
        "previous_valid_until": None,
    }
    monkeypatch.setattr(db, "switch_pair", lambda conn, pair, length: row)
    monkeypatch.setattr(db, "list_pairs", lambda conn: [])
    client, token = _client(app)
    response = client.post(
        "/pairs/p1/switch", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert pairs.NO_ROW_WARNING.format("p1").split(",")[0] in response.text
    assert "None" not in response.text
    assert 'class="secret"' not in response.text
    assert "pair p1: switch applied but no password returned" in caplog.text


# --- W6: timestamps with their UTC offset ------------------------------------------------


def test_timestamps_show_their_offset():
    paris = timezone(timedelta(hours=1))
    assert fmt_ts(datetime(2026, 10, 28, 14, 5, 59, tzinfo=paris)) == "2026-10-28 14:05+01:00"
    assert fmt_ts(datetime(2026, 10, 28, 13, 5, tzinfo=UTC)) == "2026-10-28 13:05+00:00"
    # a naive value (never returned for a timestamptz) keeps the plain form
    assert fmt_ts(datetime(2026, 10, 28, 13, 5)) == "2026-10-28 13:05"
    assert fmt_ts("infinity") == "∞ (manual)"
    assert fmt_ts(None) == "—"


# --- W7: profile delete without JavaScript -----------------------------------------------


def _profiles_page(monkeypatch, client):
    profile = {"name": "p1", "assigned_roles": 0}
    monkeypatch.setattr(db, "list_profiles", lambda conn: [profile])
    monkeypatch.setattr(db, "assignments", lambda conn: [])
    monkeypatch.setattr(db, "login_roles", lambda conn, superuser: [])
    monkeypatch.setattr(db, "session_is_superuser", lambda request, conn: False)
    response = client.get("/profiles")
    assert response.status_code == 200, response.text
    return response.text


def test_profile_delete_form_works_without_javascript(app, monkeypatch):  # noqa: F811
    client, _ = _client(app)
    page = _profiles_page(monkeypatch, client)
    form_re = r'<form method="post" action="/profiles/p1/delete"[^>]*>(.*?)</form>'
    form = re.search(form_re, page, re.S)
    assert form, page
    token = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', form.group(1))
    assert token
    dropped = []
    monkeypatch.setattr(db, "drop_profile", lambda conn, name: dropped.append(name))
    # what the browser sends without htmx: the form field, no header
    response = client.post("/profiles/p1/delete", data={"csrf_token": token.group(1)})
    assert response.status_code == 303
    assert response.headers["location"] == "/profiles"
    assert dropped == ["p1"]


def test_profile_delete_refused_without_javascript_is_a_page(app, monkeypatch):  # noqa: F811
    client, _ = _client(app)
    page = _profiles_page(monkeypatch, client)
    token = CSRF_HX_HEADERS.search(page).group(1)
    exc = psycopg.errors.ObjectInUse('pg_pass_policy: profile "p1" is assigned')
    monkeypatch.setattr(db, "drop_profile", _raise(exc))
    response = client.post("/profiles/p1/delete", data={"csrf_token": token})
    assert response.status_code == 422
    assert "<h1>Error 422</h1>" in response.text and "<nav>" in response.text


# --- W8: the token is in hx-headers only -------------------------------------------------


def test_the_token_is_only_in_hx_headers(app, monkeypatch):  # noqa: F811
    client, token = _client(app)
    page = _profiles_page(monkeypatch, client)
    assert 'name="csrf-token"' not in page
    assert CSRF_HX_HEADERS.search(page).group(1) == token
