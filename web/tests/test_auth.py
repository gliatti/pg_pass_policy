import base64

from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import TEST_PASSWORD, TEST_USER, add_probe_routes, make_settings


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_basic_missing_credentials(unit_client):
    response = unit_client.get("/_whoami")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic realm=")
    assert "text/html" in response.headers["content-type"]


def test_basic_wrong_password(unit_client):
    response = unit_client.get("/_whoami", headers=_basic(TEST_USER, "nope-nope-nope"))
    assert response.status_code == 401


def test_basic_unknown_user(unit_client):
    response = unit_client.get("/_whoami", headers=_basic("ghost", TEST_PASSWORD))
    assert response.status_code == 401


def test_basic_malformed_header(unit_client):
    assert unit_client.get("/_whoami", headers={"Authorization": "Basic %%%"}).status_code == 401
    assert unit_client.get("/_whoami", headers={"Authorization": "Bearer x"}).status_code == 401


def test_basic_ok(unit_client):
    response = unit_client.get("/_whoami", headers=_basic(TEST_USER, TEST_PASSWORD))
    assert response.status_code == 200
    assert response.json() == {"user": TEST_USER}


def test_healthz_is_public(unit_client):
    response = unit_client.get("/healthz")
    assert response.status_code == 200
    assert response.text == "ok"


def test_security_headers(unit_client):
    response = unit_client.get("/healthz")
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self' 'nonce-" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def _proxy_app():
    app = create_app(
        make_settings(
            auth="proxy",
            basic_users="",
            proxy_header="X-Remote-User",
            trusted_proxies="127.0.0.1, 10.1.0.0/16",
        )
    )
    add_probe_routes(app)
    return app


def test_proxy_trusted_peer():
    client = TestClient(_proxy_app(), client=("127.0.0.1", 40000))
    response = client.get("/_whoami", headers={"X-Remote-User": "carol"})
    assert response.status_code == 200
    assert response.json() == {"user": "carol"}


def test_proxy_trusted_network():
    client = TestClient(_proxy_app(), client=("10.1.7.7", 40000))
    assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == 200


def test_proxy_untrusted_peer_is_refused_even_with_header():
    client = TestClient(_proxy_app(), client=("192.168.1.9", 40000))
    response = client.get("/_whoami", headers={"X-Remote-User": "carol"})
    assert response.status_code == 403


def test_proxy_missing_header():
    client = TestClient(_proxy_app(), client=("127.0.0.1", 40000))
    assert client.get("/_whoami").status_code == 401
    assert client.get("/_whoami", headers={"X-Remote-User": "  "}).status_code == 401


def test_proxy_remote_user_cgi_name():
    app = create_app(make_settings(auth="proxy", basic_users="", proxy_header="REMOTE_USER"))
    add_probe_routes(app)
    client = TestClient(app, client=("127.0.0.1", 40000))
    response = client.get("/_whoami", headers={"Remote-User": "dave"})
    assert response.status_code == 200
    assert response.json() == {"user": "dave"}


def test_basic_failure_is_logged_without_password(unit_client, caplog):
    import logging

    caplog.set_level(logging.WARNING)
    secret = "nope-nope-nope"
    assert unit_client.get("/_whoami", headers=_basic(TEST_USER, secret)).status_code == 401
    assert f"basic authentication failed for user {TEST_USER} from testclient" in caplog.text
    assert secret not in caplog.text
    # a user name with control characters is logged escaped, on one line
    caplog.clear()
    assert unit_client.get("/_whoami", headers=_basic("evil\nuser", secret)).status_code == 401
    assert "'evil\\nuser'" in caplog.text
    assert "evil\nuser" not in caplog.text
    # no Authorization header at all: the browser is just being challenged
    caplog.clear()
    assert unit_client.get("/_whoami").status_code == 401
    assert "authentication failed" not in caplog.text


def test_unexpected_database_error_is_not_shown(unit_app, caplog):
    import logging

    import psycopg

    caplog.set_level(logging.ERROR)

    @unit_app.get("/_dberror")
    def dberror():
        raise psycopg.errors.InsufficientPrivilege("permission denied for table role_state")

    client = TestClient(unit_app)
    response = client.get("/_dberror", headers=_basic(TEST_USER, TEST_PASSWORD))
    assert response.status_code == 500
    assert "Database error" in response.text
    assert "role_state" not in response.text
    # the full message is in the server log
    assert "permission denied for table role_state" in caplog.text
