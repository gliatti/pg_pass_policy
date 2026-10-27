"""Integration tests against a real database (PGPP_TEST_URL), see conftest.py."""

from __future__ import annotations

import logging

import psycopg
import pytest

from tests.conftest import (
    T_GROUP,
    T_PAIR,
    T_PROFILE,
    csrf_token,
    revealed_password,
)

pytestmark = pytest.mark.usefixtures("pg_fixture")


def _audit_mentions(super_conn, needle: str) -> int:
    row = super_conn.execute(
        "SELECT count(*) FROM pass_policy.audit_log WHERE details::text LIKE %s",
        (f"%{needle}%",),
    ).fetchone()
    return row[0]


def test_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Dashboard" in body
    for status in ("ok", "warning", "grace", "expired", "locked", "never expires", "unknown"):
        assert status in body
    assert "Background worker" in body
    assert 'name="csrf-token"' in body
    assert "no-store" in response.headers["Cache-Control"]
    assert "'nonce-" in response.headers["Content-Security-Policy"]
    assert "signed in as <strong>admin</strong>" in body


def test_roles_list_and_filters(client):
    response = client.get("/roles")
    assert response.status_code == 200
    assert "web_t_alpha" in response.text and "web_t_beta" in response.text
    assert response.text.count('<tbody class="role">') >= 2

    response = client.get("/roles/table", params={"q": "web_t_al"})
    assert response.status_code == 200
    assert "web_t_alpha" in response.text and "web_t_beta" not in response.text

    response = client.get("/roles/table", params={"profile": T_PROFILE})
    assert "web_t_alpha" in response.text and "pgpp_web" not in response.text

    response = client.get("/roles/table", params={"status": "locked"})
    assert response.status_code == 200
    assert "web_t_alpha" not in response.text


def test_rotate_password_shown_once_and_never_logged(client, super_conn, caplog, test_url):
    caplog.set_level(logging.DEBUG)
    token = csrf_token(client, "/roles")
    response = client.post(
        "/roles/web_t_alpha/rotate", data={"length": "28"}, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    password = revealed_password(response.text)
    assert len(password) == 28
    assert "shown once" in response.text
    assert "web_t_alpha" in response.text
    # the fragment replaces the whole <tbody> of the role (row + note), so the
    # next action on the same role also removes the revealed password
    assert response.text.lstrip().startswith('<tbody class="role">')
    assert response.text.rstrip().endswith("</tbody>")
    assert 'hx-target="closest tbody"' in response.text
    assert "closest tr" not in response.text

    # never in the application logs, never in the audit trail
    assert password not in caplog.text
    assert _audit_mentions(super_conn, password) == 0
    event = super_conn.execute(
        "SELECT actor, application_name, details FROM pass_policy.audit_log"
        " WHERE event_type = 'password_rotated' AND role_name = 'web_t_alpha'"
        " ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert event is not None
    assert event[1] == "pgpp-web:admin"
    assert event[2]["length"] == 28

    # the new password actually works (passed as a connection parameter, not in the URL)
    with psycopg.connect(test_url, user="web_t_alpha", password=password) as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == "web_t_alpha"

    # the roles table does not carry the password either
    listing = client.get("/roles/table", params={"q": "web_t_alpha"})
    assert password not in listing.text

    # a GET on the rotate URL is not an action
    assert client.get("/roles/web_t_alpha/rotate").status_code == 405


def test_rotate_unknown_role_shows_error(client):
    token = csrf_token(client, "/roles")
    response = client.post("/roles/web_t_nope/rotate", headers={"X-CSRF-Token": token})
    assert response.status_code == 422
    assert "does not exist" in response.text


def test_lock_unlock(client, super_conn):
    token = csrf_token(client, "/roles")
    headers = {"X-CSRF-Token": token}
    response = client.post(
        "/roles/web_t_beta/lock", data={"duration": "1 hour", "reason": "web test"}, headers=headers
    )
    assert response.status_code == 200, response.text
    assert "Role locked" in response.text
    assert 'status-locked">locked' in response.text
    assert "web test" in response.text
    row = super_conn.execute(
        "SELECT status, locked_until > now() FROM pass_policy.v_role_status"
        " WHERE role_name = 'web_t_beta'"
    ).fetchone()
    assert row == ("locked", True)
    # the locked row offers Unlock, not Lock
    assert "/roles/web_t_beta/unlock" in response.text
    assert "/roles/web_t_beta/lock" not in response.text

    response = client.post("/roles/web_t_beta/unlock", headers=headers)
    assert response.status_code == 200, response.text
    assert "Role unlocked" in response.text
    assert 'status-locked">locked' not in response.text
    row = super_conn.execute(
        "SELECT status FROM pass_policy.v_role_status WHERE role_name = 'web_t_beta'"
    ).fetchone()
    assert row[0] != "locked"

    # manual lock (no duration): locked until unlock ('infinity' is rendered, not a crash)
    response = client.post("/roles/web_t_beta/lock", data={"duration": ""}, headers=headers)
    assert response.status_code == 200, response.text
    assert "∞ (manual)" in response.text
    assert client.get("/roles/table", params={"status": "locked"}).text.count("web_t_beta") >= 1
    assert client.post("/roles/web_t_beta/unlock", headers=headers).status_code == 200


def test_expire_then_rotate(client, super_conn):
    token = csrf_token(client, "/roles")
    headers = {"X-CSRF-Token": token}
    response = client.post("/roles/web_t_beta/expire", headers=headers)
    assert response.status_code == 200, response.text
    assert "Password expired" in response.text
    assert 'status-expired">expired' in response.text
    assert "must change" in response.text
    response = client.post("/roles/web_t_beta/rotate", headers=headers)
    assert response.status_code == 200, response.text
    revealed_password(response.text)
    assert 'status-expired">expired' not in response.text


def test_csrf_enforced_on_actions(client):
    client.get("/roles")
    response = client.post("/roles/web_t_alpha/unlock")
    assert response.status_code == 403
    response = client.post("/roles/web_t_alpha/unlock", headers={"X-CSRF-Token": "wrong"})
    assert response.status_code == 403


def test_profiles_crud_and_assignment(client, super_conn):
    token = csrf_token(client, "/profiles")
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}

    page = client.get("/profiles")
    assert page.status_code == 200
    assert "default" in page.text and T_PROFILE in page.text

    form = client.get("/profiles/new")
    assert form.status_code == 200
    assert 'name="min_length"' in form.text

    data = {
        "name": "web_t_created",
        "min_length": "14",
        "max_length": "64",
        "min_lower": "1",
        "min_upper": "1",
        "min_digit": "1",
        "min_special": "0",
        "min_classes": "3",
        "reject_username": "true",
        "reject_dictionary": "true",
        "max_repeat": "3",
        "history_count": "3",
        "history_days": "180",
        "max_age": "",
        "min_age": "0",
        "grace_period": "3 days",
        "warn_before": "7 days",
        "max_failures": "4",
        "failure_window": "10 minutes",
        "lock_duration": "",
    }
    response = client.post("/profiles", data=data, headers=headers)
    assert response.status_code == 204, response.text
    assert response.headers["HX-Redirect"].endswith("/profiles")
    row = super_conn.execute(
        "SELECT min_length, max_age, lock_duration, reject_prehashed FROM pass_policy.profile"
        " WHERE name = 'web_t_created'"
    ).fetchone()
    assert row == (14, None, None, False)

    # duplicate name -> error in the form
    response = client.post("/profiles", data=data, headers=headers)
    assert response.status_code == 422
    assert "already exists" in response.text

    # invalid value -> error without touching the database
    bad = {**data, "name": "web_t_bad", "min_length": "abc"}
    response = client.post("/profiles", data=bad, headers=headers)
    assert response.status_code == 422 and "not an integer" in response.text

    edit = client.get("/profiles/web_t_created")
    assert edit.status_code == 200
    assert 'value="14"' in edit.text
    response = client.post(
        "/profiles/web_t_created",
        data={**data, "min_length": "16", "max_age": "30 days"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert "Profile updated" in response.text
    row = super_conn.execute(
        "SELECT min_length, max_age::text FROM pass_policy.profile WHERE name = 'web_t_created'"
    ).fetchone()
    assert row == (16, "30 days")

    response = client.post(
        "/profiles/assign", data={"role": "web_t_beta", "profile": "web_t_created"}, headers=headers
    )
    assert response.status_code == 200, response.text
    assert "assigned to web_t_beta" in response.text
    listing = client.get("/roles/table", params={"q": "web_t_beta"})
    assert "web_t_created" in listing.text

    # assigned profiles cannot be dropped
    response = client.post("/profiles/web_t_created/delete", headers=headers)
    assert response.status_code == 422 and "assigned" in response.text

    response = client.post("/profiles/unassign", data={"role": "web_t_beta"}, headers=headers)
    assert response.status_code == 200
    assert "back on the default profile" in response.text
    # restore the test profile for the other tests
    client.post(
        "/profiles/assign", data={"role": "web_t_beta", "profile": T_PROFILE}, headers=headers
    )

    response = client.post("/profiles/web_t_created/delete", headers=headers)
    assert response.status_code == 204
    assert (
        super_conn.execute(
            "SELECT count(*) FROM pass_policy.profile WHERE name = 'web_t_created'"
        ).fetchone()[0]
        == 0
    )

    response = client.post("/profiles/default/delete", headers=headers)
    assert response.status_code == 422 and "cannot be dropped" in response.text


def test_privileged_role_cannot_be_assigned_by_non_superuser(client, super_conn, test_url):
    with psycopg.connect(test_url) as conn:
        if conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = session_user").fetchone()[0]:
            pytest.skip("the web service role is a superuser")
    superuser = super_conn.execute(
        "SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin ORDER BY 1 LIMIT 1"
    ).fetchone()[0]
    token = csrf_token(client, "/profiles")
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}

    # not offered in the assignment form...
    page = client.get("/profiles")
    assert f'<option value="{superuser}">' not in page.text
    assert '<option value="web_t_alpha">' in page.text
    # ...and refused when the form value is forged
    for path, data in (
        ("/profiles/assign", {"role": superuser, "profile": T_PROFILE}),
        ("/profiles/unassign", {"role": superuser}),
    ):
        response = client.post(path, data=data, headers=headers)
        assert response.status_code == 422, response.text
        assert f"only a superuser can manage privileged role &#34;{superuser}&#34;" in response.text
    assert (
        super_conn.execute(
            "SELECT count(*) FROM pass_policy.role_profile WHERE role_name = %s", (superuser,)
        ).fetchone()[0]
        == 0
    )


def test_audit_filters_and_pagination(client):
    token = csrf_token(client, "/roles")
    for _ in range(3):
        client.post("/roles/web_t_alpha/rotate", headers={"X-CSRF-Token": token})

    page = client.get("/audit")
    assert page.status_code == 200
    assert "password_rotated" in page.text

    response = client.get(
        "/audit/table",
        params={"role": "web_t_alpha", "type": "password_rotated", "since": "1 hour"},
    )
    assert response.status_code == 200
    assert "web_t_alpha" in response.text
    assert "pgpp-web:admin" in response.text
    assert "password_changed" not in response.text

    response = client.get("/audit/table", params={"since": "2000-01-01"})
    assert response.status_code == 200 and "event" in response.text

    response = client.get("/audit/table", params={"since": "not a date"})
    assert response.status_code == 200
    assert "Invalid filter" in response.text

    # pagination with a tiny page size
    client.app.state.settings.page_size = 2
    first = client.get("/audit/table", params={"role": "web_t_alpha", "page": 1})
    second = client.get("/audit/table", params={"role": "web_t_alpha", "page": 2})
    assert "page 1 /" in first.text and "page 2 /" in second.text
    assert "next →" in first.text and "← previous" in second.text
    ids_first = {line for line in first.text.splitlines() if "<tr><td>" in line}
    ids_second = {line for line in second.text.splitlines() if "<tr><td>" in line}
    assert ids_first and ids_second and ids_first.isdisjoint(ids_second)


def test_rotation_pairs(client, super_conn, caplog):
    caplog.set_level(logging.DEBUG)
    token = csrf_token(client, "/pairs")
    headers = {"X-CSRF-Token": token}
    response = client.post(
        "/pairs",
        data={
            "pair_name": T_PAIR,
            "role_a": "web_t_pa",
            "role_b": "web_t_pb",
            "group_role": T_GROUP,
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert f"Rotation pair {T_PAIR} created" in response.text
    assert super_conn.execute(
        "SELECT pg_has_role('web_t_pa', %s, 'MEMBER')", (T_GROUP,)
    ).fetchone()[0]

    response = client.post(f"/pairs/{T_PAIR}/switch", data={"length": "30"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    password = revealed_password(response.text)
    assert len(password) == 30
    assert "active role is now <code>web_t_pa</code>" in response.text
    assert password not in caplog.text
    assert _audit_mentions(super_conn, password) == 0

    response = client.post(f"/pairs/{T_PAIR}/switch", headers=headers)
    assert response.status_code == 200, response.text
    assert "active role is now <code>web_t_pb</code>" in response.text
    assert "<code>web_t_pa</code> stays valid until" in response.text

    response = client.post("/pairs/does_not_exist/switch", headers=headers)
    assert response.status_code == 422 and "does not exist" in response.text

    page = client.get("/pairs")
    assert T_PAIR in page.text and "web_t_pb" in page.text


def test_maintenance(client):
    page = client.get("/maintenance")
    assert page.status_code == 200
    token = csrf_token(client, "/maintenance")
    response = client.post("/maintenance/run", headers={"X-CSRF-Token": token})
    assert response.status_code == 200, response.text
    assert "Maintenance completed" in response.text


def test_static_assets_served(client):
    response = client.get("/static/htmx.min.js")
    assert response.status_code == 200
    assert "htmx" in response.text[:200]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/app.css").status_code == 200
