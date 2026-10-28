"""Shared fixtures.

Unit tests build the app without opening the pool (no lifespan).
Integration tests need PGPP_TEST_URL (connection string of a role member of
pass_policy_admin on a database where pg_pass_policy is installed) and,
optionally, PGPP_TEST_SUPER_URL (a superuser, used to create and drop the
test roles); they are skipped otherwise.  web/scripts/test-instance.sh starts
such an instance and prints the variables to export.
"""

from __future__ import annotations

import html
import os
import re

import bcrypt
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TEST_USER = "admin"
TEST_PASSWORD = "web-test-password-1"
# low cost: these hashes only protect a test client
TEST_HASH = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
SECRET = "unit-test-secret-key-of-at-least-32-chars"


def make_settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql://127.0.0.1:1/nowhere",
        "auth": "basic",
        "basic_users": f"{TEST_USER}:{TEST_HASH}",
        "secret": SECRET,
        "pool_min": 1,
        "pool_max": 2,
        "pool_timeout": 5.0,
    }
    values.update(overrides)
    return Settings(**values)


def add_probe_routes(app) -> None:
    """Routes that touch no database, used by the unit tests."""

    @app.get("/_whoami", name="whoami")
    def whoami(request: Request) -> dict[str, str | None]:
        return {"user": request.state.user}

    @app.post("/_echo", name="echo")
    async def echo(request: Request) -> dict[str, str]:
        form = await request.form()
        return {k: str(v) for k, v in form.items()}


@pytest.fixture
def unit_app():
    app = create_app(make_settings())
    add_probe_routes(app)
    return app


@pytest.fixture
def unit_client(unit_app):
    # no `with`: the lifespan (pool) is not started
    return TestClient(unit_app)


# the token is only in hx-headers on <body> (base.html), sent by htmx
CSRF_HX_HEADERS = re.compile(r"""hx-headers='\{"X-CSRF-Token": "([^"]+)"\}'""")


def csrf_token(client: TestClient, path: str = "/healthz") -> str:
    """Fetch a page to obtain the session cookie and read the CSRF token from it."""
    response = client.get(path)
    assert response.status_code == 200, response.text
    match = CSRF_HX_HEADERS.search(response.text)
    if match:
        return match.group(1)
    # a page without base.html (e.g. /healthz): read the token through the probe
    response = client.get("/_csrf")
    assert response.status_code == 200
    return response.json()["token"]


SECRET_RE = re.compile(r'<code id="pw-[0-9a-f]+" class="secret">([^<]+)</code>')


def revealed_password(text: str) -> str:
    match = SECRET_RE.search(text)
    assert match, "no one-time password in the response"
    return html.unescape(match.group(1))


# --- integration ---------------------------------------------------------------


@pytest.fixture(scope="session")
def test_url() -> str:
    url = os.environ.get("PGPP_TEST_URL")
    if not url:
        pytest.skip("PGPP_TEST_URL not set: integration tests skipped")
    return url


@pytest.fixture(scope="session")
def super_url(test_url) -> str:
    return os.environ.get("PGPP_TEST_SUPER_URL") or test_url


@pytest.fixture(scope="session")
def super_conn(super_url):
    import psycopg

    with psycopg.connect(super_url, autocommit=True) as conn:
        yield conn


# T_SLASH: a role name that needs percent-encoding in the action URLs
T_SLASH = "web_t_app/batch?#%"
T_ROLES = ("web_t_alpha", "web_t_beta", "web_t_pa", "web_t_pb", T_SLASH)
T_GROUP = "web_t_group"
T_PROFILE = "web_t_profile"
T_PAIR = "web_t_pair"


def _cleanup(conn) -> None:
    from psycopg import sql

    conn.execute("DELETE FROM pass_policy.rotation_pair WHERE pair_name LIKE 'web_t_%'")
    conn.execute(
        "DELETE FROM pass_policy.role_profile WHERE profile_id IN"
        " (SELECT profile_id FROM pass_policy.profile WHERE name LIKE 'web_t_%')"
    )
    conn.execute("DELETE FROM pass_policy.profile WHERE name LIKE 'web_t_%'")
    for role in (*T_ROLES, T_GROUP):
        conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture(scope="session")
def pg_fixture(super_conn):
    """Test roles and a profile without min_age so that passwords can be rotated at will."""
    from psycopg import sql

    _cleanup(super_conn)
    super_conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(T_GROUP)))
    for role in ("web_t_alpha", "web_t_beta", T_SLASH):
        super_conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
    super_conn.execute(
        "SELECT pass_policy.create_profile(%s, %s::jsonb)",
        (T_PROFILE, '{"min_age": "0", "lock_duration": "1 hour"}'),
    )
    for role in ("web_t_alpha", "web_t_beta", T_SLASH):
        super_conn.execute("SELECT pass_policy.assign_profile(%s, %s)", (role, T_PROFILE))
    yield
    _cleanup(super_conn)


@pytest.fixture
def client(test_url, pg_fixture, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    app = create_app(make_settings(database_url=test_url))
    with TestClient(app) as c:
        c.auth = (TEST_USER, TEST_PASSWORD)
        yield c
