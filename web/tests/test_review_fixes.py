"""Unit tests: root_path, CSRF token encoding, validation errors, URL encoding."""

from __future__ import annotations

import base64
import html
from urllib.parse import quote

import psycopg
import pytest
from fastapi import HTTPException, Query, Request
from fastapi.testclient import TestClient

from app import db
from app.main import create_app
from app.security import route_path
from app.templating import _context, render
from tests.conftest import TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings

_TOKEN = base64.b64encode(f"{TEST_USER}:{TEST_PASSWORD}".encode()).decode()
AUTH = {"Authorization": f"Basic {_TOKEN}"}


@pytest.mark.parametrize(
    ("path", "root_path", "expected"),
    [
        ("/healthz", "", "/healthz"),
        ("/pgpp/healthz", "/pgpp", "/healthz"),
        # same as Starlette's router: the root path itself is "", not "/"
        ("/pgpp", "/pgpp", ""),
        ("/pgpp/", "/pgpp", "/"),
        ("/pgppx/healthz", "/pgpp", "/pgppx/healthz"),
        # server that does not prefix scope["path"] with root_path
        ("/healthz", "/pgpp", "/healthz"),
    ],
)
def test_route_path(path, root_path, expected):
    assert route_path({"path": path, "root_path": root_path}) == expected


# --- W1: behind `uvicorn --root-path /pgpp` --------------------------------------


@pytest.fixture
def prefixed_client():
    app = create_app(make_settings())
    add_probe_routes(app)
    # like uvicorn >= 0.26: root_path in the scope and in front of the path
    return TestClient(app, root_path="/pgpp")


def test_healthz_public_behind_root_path(prefixed_client):
    response = prefixed_client.get("/pgpp/healthz")
    assert response.status_code == 200
    assert response.text == "ok"


def test_static_cache_behind_root_path(prefixed_client):
    response = prefixed_client.get("/pgpp/static/app.css")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "public, max-age=3600"


def test_auth_still_required_behind_root_path(prefixed_client):
    assert prefixed_client.get("/pgpp/_whoami").status_code == 401
    response = prefixed_client.get("/pgpp/_whoami", headers=AUTH)
    assert response.status_code == 200 and response.json() == {"user": TEST_USER}


def test_active_nav_and_links_behind_root_path(prefixed_client):
    # an error raised after authentication (no database needed) is rendered
    # with base.html and its navigation
    @prefixed_client.app.get("/roles/_missing")
    def missing() -> None:
        raise HTTPException(status_code=404, detail="nothing here")

    response = prefixed_client.get("/pgpp/roles/_missing", headers=AUTH)
    assert response.status_code == 404
    assert '<a href="/pgpp/roles" class="active">Roles</a>' in response.text
    assert '<a href="/pgpp/" class="active">' not in response.text
    assert 'href="/pgpp/static/app.css?v=' in response.text


# --- W4: non-ASCII CSRF token -----------------------------------------------------


def test_non_ascii_csrf_token_is_refused_not_500(unit_app):
    client = TestClient(unit_app)
    client.auth = (TEST_USER, TEST_PASSWORD)
    client.get("/_csrf")
    response = client.post("/_echo", data={"csrf_token": "é"})
    assert response.status_code == 403
    response = client.post("/_echo", headers={"X-CSRF-Token": "é".encode()})
    assert response.status_code == 403


@pytest.fixture
def unit_app(unit_app):
    from app.csrf import get_csrf_token

    @unit_app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    @unit_app.get("/_page")
    def page(n: int = Query(ge=1)) -> dict[str, int]:
        return {"n": n}

    @unit_app.get("/_link/{role:path}/rotate", name="_link")
    def link(request: Request, role: str):
        return render(request, "_alert.html", {"notice": role})

    return unit_app


# --- W5: validation errors rendered as HTML ------------------------------------------


def test_validation_error_is_an_html_fragment_for_htmx(unit_app):
    client = TestClient(unit_app)
    response = client.get("/_page", params={"n": "0"}, headers={**AUTH, "HX-Request": "true"})
    assert response.status_code == 422
    assert "text/html" in response.headers["content-type"]
    assert "Invalid request: n:" in response.text
    assert '"detail"' not in response.text


def test_validation_error_is_an_html_page(unit_app):
    client = TestClient(unit_app)
    response = client.get("/_page", params={"n": "abc"}, headers=AUTH)
    assert response.status_code == 422
    assert "text/html" in response.headers["content-type"]
    assert "Error 422" in response.text
    # the submitted value is not echoed back
    assert "abc" not in response.text


def test_validation_error_does_not_bypass_authentication(unit_app):
    response = TestClient(unit_app).get("/_page", params={"n": "0"})
    assert response.status_code == 401


# --- W3: role names with '/', '?', '#', '%' ------------------------------------------


@pytest.mark.parametrize("role", ["app/batch", "a?b", "a#b", "50%", 'q"uote', "é"])
def test_path_for_encodes_and_round_trips(unit_app, role):
    client = TestClient(unit_app)
    path = f"/_link/{quote(role, safe='')}/rotate"
    response = client.get(path, headers=AUTH)
    assert response.status_code == 200, response.text
    assert f">{role}<" in html.unescape(response.text)


def test_role_action_urls_are_encoded(unit_app):
    request_scope = {
        "type": "http",
        "path": "/",
        "root_path": "",
        "headers": [],
        "query_string": b"",
        "app": unit_app,
        "router": unit_app.router,
        "state": {},
        "server": ("testserver", 80),
        "scheme": "http",
    }
    request = Request(request_scope)
    path_for = _context(request)["path_for"]
    assert path_for("role_rotate", role="app/batch") == "/roles/app%2Fbatch/rotate"
    assert path_for("role_lock", role="a?b#c") == "/roles/a%3Fb%23c/lock"
    assert path_for("pair_switch", pair="p/1") == "/pairs/p%2F1/switch"


# --- W2: worker_status() failure -----------------------------------------------------


class _FakeTransaction:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.savepoints += 1
        return self

    def __exit__(self, *exc):
        self.conn.rolled_back = exc[0] is not None
        return False


class _FakeConn:
    def __init__(self):
        self.savepoints = 0
        self.rolled_back = False

    def transaction(self):
        return _FakeTransaction(self)

    message = "pg_pass_policy worker state unavailable"

    def execute(self, *args, **kwargs):
        raise psycopg.errors.ObjectNotInPrerequisiteState(self.message)


def test_worker_status_error_returns_none_inside_a_savepoint():
    conn = _FakeConn()
    assert db.worker_status(conn) is None  # type: ignore[arg-type]
    assert conn.savepoints == 1 and conn.rolled_back


def test_worker_status_not_preloaded_propagates_after_the_savepoint():
    """The library not preloaded is not "worker not running": the request
    gets the dedicated page (tests/test_review_round7.py)."""
    conn = _FakeConn()
    conn.message = "pg_pass_policy must be loaded via shared_preload_libraries"
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        db.worker_status(conn)  # type: ignore[arg-type]
    assert conn.savepoints == 1 and conn.rolled_back


def test_unknown_path_is_an_html_page(unit_app):
    """The router's own 404 / 405 go through the HTML error handler too."""
    client = TestClient(unit_app)
    response = client.get("/no/such/page", headers=AUTH)
    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"] and "Error 404" in response.text
    response = client.get("/healthz", headers={"HX-Request": "true"})
    assert response.status_code == 200
    response = client.delete("/healthz", headers={"HX-Request": "true"})
    assert response.status_code == 405
    assert '<div class="alert alert-error" role="alert">' in response.text
