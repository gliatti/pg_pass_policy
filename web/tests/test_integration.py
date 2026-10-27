"""Integration tests against a real database (PGPP_TEST_URL), see conftest.py."""

from __future__ import annotations

import logging

import psycopg
import pytest

from tests.conftest import (
    T_GROUP,
    T_PAIR,
    T_PROFILE,
    T_SLASH,
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


def test_role_name_needing_url_encoding(client, super_conn):
    """A role name with '/', '?', '#' and '%' (W3): the page renders, the
    action URLs are percent-encoded and reach the right role."""
    from urllib.parse import quote

    encoded = quote(T_SLASH, safe="")
    page = client.get("/roles")
    assert page.status_code == 200, page.text
    assert f'hx-post="/roles/{encoded}/rotate"' in page.text
    token = csrf_token(client, "/roles")
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}

    response = client.post(f"/roles/{encoded}/rotate", headers=headers)
    assert response.status_code == 200, response.text
    revealed_password(response.text)
    assert f'hx-post="/roles/{encoded}/lock"' in response.text

    response = client.post(f"/roles/{encoded}/lock", data={"duration": "1 hour"}, headers=headers)
    assert response.status_code == 200, response.text
    assert super_conn.execute(
        "SELECT status FROM pass_policy.v_role_status WHERE role_name = %s", (T_SLASH,)
    ).fetchone() == ("locked",)
    response = client.post(f"/roles/{encoded}/unlock", headers=headers)
    assert response.status_code == 200 and "Role unlocked" in response.text
    # the other roles were not touched
    assert super_conn.execute(
        "SELECT count(*) FROM pass_policy.v_role_status"
        " WHERE status = 'locked' AND role_name LIKE 'web_t_app%%'"
    ).fetchone() == (0,)

    # a pair name with '/' reaches the switch handler, decoded
    response = client.post(f"/pairs/{quote('web_t_x/y', safe='')}/switch", headers=headers)
    assert response.status_code == 422
    assert "does not exist" in response.text and "web_t_x/y" in response.text


def test_worker_status_unavailable(client, monkeypatch):
    """worker_status() failing (library not preloaded, W2): the pages render
    the "not running" branch and the rest of the transaction still works."""
    from app import db

    monkeypatch.setattr(db, "WORKER_STATUS_SQL", "SELECT * FROM pass_policy.no_such_function()")
    response = client.get("/")
    assert response.status_code == 200, response.text
    assert "The background worker is not running" in response.text
    assert "Full audit log" in response.text
    response = client.get("/maintenance")
    assert response.status_code == 200, response.text
    assert "Worker pid" not in response.text
    token = csrf_token(client, "/maintenance")
    response = client.post("/maintenance/run", headers={"X-CSRF-Token": token})
    assert response.status_code == 200 and "Maintenance completed" in response.text


def test_validation_errors_are_html(client):
    """FastAPI's 422 JSON body never reaches the page (W5)."""
    token = csrf_token(client, "/roles")
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    # (an empty field is not an error: FastAPI applies the default, 24)
    response = client.post("/roles/web_t_alpha/rotate", data={"length": "4"}, headers=headers)
    assert response.status_code == 422
    assert "text/html" in response.headers["content-type"]
    assert '<div class="alert alert-error" role="alert">Invalid request: length:' in response.text
    response = client.post("/roles/web_t_alpha/rotate", data={"length": "abc"}, headers=headers)
    assert response.status_code == 422 and "Invalid request: length:" in response.text
    assert "abc" not in response.text

    response = client.get("/audit", params={"page": "0"})
    assert response.status_code == 422
    assert "Error 422" in response.text and "Invalid request: page:" in response.text
    response = client.get("/audit/table", params={"page": "x"}, headers={"HX-Request": "true"})
    assert response.status_code == 422 and "Invalid request: page:" in response.text


def test_audit_page_past_the_end_keeps_the_total(client):
    first = client.get("/audit/table", params={"role": "web_t_alpha"})
    far = client.get("/audit/table", params={"role": "web_t_alpha", "page": 99999})
    assert far.status_code == 200
    assert "No event matches." in far.text
    total = first.text.split(" event", 1)[0].rsplit(">", 1)[1]
    assert int(total) > 0
    assert f"{total} event" in far.text


def test_profile_name_cannot_contain_a_slash(client, super_conn):
    """Profile routes keep a single-segment {name}: the CHECK constraint of
    pass_policy.profile forbids '/', so "x/delete" (which would be routed as
    the delete action on "x" once %2F is decoded) can never exist."""
    super_conn.execute("SELECT pass_policy.create_profile('web_t_x', '{}')")
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            super_conn.execute("SELECT pass_policy.create_profile('web_t_x/delete', '{}')")
        with pytest.raises(psycopg.errors.CheckViolation):
            super_conn.execute(
                "UPDATE pass_policy.profile SET name = 'web_t_x/delete' WHERE name = 'web_t_x'"
            )

        token = csrf_token(client, "/profiles")
        headers = {"X-CSRF-Token": token, "HX-Request": "true"}
        data = {
            "name": "web_t_x/delete",
            "min_length": "12",
            "max_length": "128",
            "min_lower": "1",
            "min_upper": "1",
            "min_digit": "1",
            "min_special": "1",
            "min_classes": "3",
            "max_repeat": "3",
            "history_count": "5",
            "history_days": "365",
            "max_age": "90 days",
            "min_age": "1 day",
            "grace_period": "7 days",
            "warn_before": "14 days",
            "max_failures": "5",
            "failure_window": "15 minutes",
            "lock_duration": "30 minutes",
        }
        response = client.post("/profiles", data=data, headers=headers)
        assert response.status_code == 422, response.text
        assert "profile_name_check" in response.text or "check constraint" in response.text
        assert super_conn.execute(
            "SELECT count(*) FROM pass_policy.profile WHERE name LIKE '%%/%%'"
        ).fetchone() == (0,)
        # "web_t_x" is untouched
        assert super_conn.execute(
            "SELECT count(*) FROM pass_policy.profile WHERE name = 'web_t_x'"
        ).fetchone() == (1,)
    finally:
        super_conn.execute("SELECT pass_policy.drop_profile('web_t_x')")


def test_htmx_validation_error_keeps_the_role_row(client):
    """A 422 on a role row action is shown in the page's alert area
    (HX-Retarget), the row's <tbody> is not replaced by a bare alert."""
    token = csrf_token(client, "/roles")
    page = client.get("/roles")
    assert '<div id="alerts" aria-live="polite"></div>' in page.text
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    response = client.post("/roles/web_t_alpha/rotate", data={"length": "4"}, headers=headers)
    assert response.status_code == 422
    assert response.headers["HX-Retarget"] == "#alerts"
    assert response.headers["HX-Reswap"] == "innerHTML"
    # an action error from the extension still replaces the row itself
    response = client.post("/roles/web_t_no_such_role/expire", headers=headers)
    assert response.status_code == 422
    assert "HX-Retarget" not in response.headers
    assert response.text.lstrip().startswith('<tbody class="role">')


PROFILE_FORM = {
    "min_length": "12",
    "max_length": "128",
    "min_lower": "1",
    "min_upper": "1",
    "min_digit": "1",
    "min_special": "0",
    "min_classes": "3",
    "max_repeat": "3",
    "history_count": "5",
    "history_days": "365",
    "max_age": "",
    "min_age": "0",
    "grace_period": "7 days",
    "warn_before": "14 days",
    "max_failures": "5",
    "failure_window": "15 minutes",
    "lock_duration": "",
}


def test_profile_created_is_listed_immediately(client, super_conn):
    """The request transaction is committed before the 303 / HX-Redirect
    (scope="function"): the GET that follows sees the new profile."""
    token = csrf_token(client, "/profiles")
    try:
        for name, headers in (
            ("web_t_now1", {"X-CSRF-Token": token}),
            ("web_t_now2", {"X-CSRF-Token": token, "HX-Request": "true"}),
        ):
            response = client.post(
                "/profiles",
                data={"name": name, **PROFILE_FORM},
                headers=headers,
                follow_redirects=False,
            )
            assert response.status_code in (204, 303), response.text
            listing = client.get("/profiles")
            assert f'href="/profiles/{name}"' in listing.text or name in listing.text
            assert super_conn.execute(
                "SELECT count(*) FROM pass_policy.profile WHERE name = %s", (name,)
            ).fetchone() == (1,)
        # plain form post: the redirect is followed to the listing
        response = client.post(
            "/profiles/web_t_now1/delete", data={"csrf_token": token}, follow_redirects=True
        )
        assert response.status_code == 200 and "web_t_now1" not in response.text
    finally:
        super_conn.execute("DELETE FROM pass_policy.profile WHERE name LIKE 'web_t_now%'")


def test_reserved_profile_names_are_refused(client, super_conn):
    token = csrf_token(client, "/profiles")
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    for name in ("new", "assign", "unassign", ".", ".."):
        response = client.post("/profiles", data={"name": name, **PROFILE_FORM}, headers=headers)
        assert response.status_code == 422, (name, response.text)
        assert "is reserved by the web interface" in response.text
    assert super_conn.execute(
        "SELECT count(*) FROM pass_policy.profile"
        " WHERE name IN ('new', 'assign', 'unassign', '.', '..')"
    ).fetchone() == (0,)


PRIV_ROLES = {
    # role: (CREATE ROLE options, granted roles)
    "web_t_priv_plain": ("LOGIN", ()),
    "web_t_priv_createrole": ("LOGIN CREATEROLE", ()),
    "web_t_priv_repl": ("LOGIN REPLICATION", ()),
    "web_t_priv_bypass": ("LOGIN BYPASSRLS", ()),
    "web_t_priv_pgfiles": ("LOGIN", ("pg_read_server_files",)),
    "web_t_priv_group": ("NOLOGIN", ("pg_monitor",)),
    "web_t_priv_indirect": ("LOGIN", ("web_t_priv_group",)),
    "web_t_priv_dbowner": ("LOGIN", ("pg_database_owner",)),
}


# PostgreSQL >= 16: CREATEROLE alone is not privileged; pg_database_owner is
# excluded by the rule
EXPECTED_REFUSED = {
    "web_t_priv_repl",
    "web_t_priv_bypass",
    "web_t_priv_pgfiles",
    "web_t_priv_group",
    "web_t_priv_indirect",
}


def test_privileged_rule_agrees_with_the_extension(client, super_conn, test_url):
    """db._PRIVILEGED_ROLE (assignment form and refusal) must agree with
    pass_policy._require_target_allowed(): expire_password() is the oracle,
    called by the service role in a transaction that is rolled back."""
    from psycopg import sql

    from app import db

    with psycopg.connect(test_url) as conn:
        if conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = session_user").fetchone()[0]:
            pytest.skip("the web service role is a superuser")

    def drop_all():
        for role in reversed(list(PRIV_ROLES)):
            super_conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))

    drop_all()
    try:
        for role, (options, granted) in PRIV_ROLES.items():
            super_conn.execute(sql.SQL("CREATE ROLE {} " + options).format(sql.Identifier(role)))
            for g in granted:
                try:
                    super_conn.execute(
                        sql.SQL("GRANT {} TO {}").format(sql.Identifier(g), sql.Identifier(role))
                    )
                except psycopg.Error:
                    pass  # pg_database_owner cannot be granted explicitly
        superuser = super_conn.execute(
            "SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin ORDER BY 1 LIMIT 1"
        ).fetchone()[0]
        candidates = [*PRIV_ROLES, superuser, "pgpp_web"]

        from psycopg.rows import dict_row

        with psycopg.connect(test_url, row_factory=dict_row) as conn:
            offered = set(db.login_roles(conn, superuser=False))
            for role in candidates:
                try:
                    with conn.transaction(force_rollback=True):
                        conn.execute("SELECT pass_policy.expire_password(%s)", (role,))
                    extension_refuses = False
                except psycopg.errors.InsufficientPrivilege:
                    extension_refuses = True
                web_refuses = db.privileged_target_refused(conn, role, superuser=False)
                assert web_refuses is extension_refuses, role
                login = super_conn.execute(
                    "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (role,)
                ).fetchone()[0]
                assert (role in offered) is (login and not extension_refuses), role
                assert extension_refuses is (role in EXPECTED_REFUSED or role == superuser), role
        token = csrf_token(client, "/profiles")
        response = client.post(
            "/profiles/assign",
            data={"role": "web_t_priv_indirect", "profile": T_PROFILE},
            headers={"X-CSRF-Token": token, "HX-Request": "true"},
        )
        assert response.status_code == 422
        assert "only a superuser can manage privileged role" in response.text
    finally:
        super_conn.execute(
            "DELETE FROM pass_policy.role_profile WHERE role_name LIKE 'web_t_priv_%'"
        )
        drop_all()
