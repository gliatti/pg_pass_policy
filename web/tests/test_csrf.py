import re

from fastapi import Request

from app.csrf import get_csrf_token
from tests.conftest import TEST_PASSWORD, TEST_USER


def _client(unit_app):
    from fastapi.testclient import TestClient

    @unit_app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    client = TestClient(unit_app)
    client.auth = (TEST_USER, TEST_PASSWORD)
    return client


def test_post_without_token_is_refused(unit_app):
    client = _client(unit_app)
    client.get("/_csrf")  # creates the session
    response = client.post("/_echo", data={"a": "1"})
    assert response.status_code == 403
    assert "CSRF" in response.text


def test_post_with_wrong_token_is_refused(unit_app):
    client = _client(unit_app)
    client.get("/_csrf")
    response = client.post("/_echo", data={"a": "1", "csrf_token": "bogus"})
    assert response.status_code == 403
    response = client.post("/_echo", data={"a": "1"}, headers={"X-CSRF-Token": "bogus"})
    assert response.status_code == 403


def test_post_without_session_is_refused(unit_app):
    client = _client(unit_app)
    response = client.post("/_echo", data={"a": "1"}, headers={"X-CSRF-Token": "anything"})
    assert response.status_code == 403


def test_post_with_header_token(unit_app):
    client = _client(unit_app)
    token = client.get("/_csrf").json()["token"]
    response = client.post("/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.json() == {"a": "1"}


def test_post_with_form_token(unit_app):
    client = _client(unit_app)
    token = client.get("/_csrf").json()["token"]
    response = client.post("/_echo", data={"a": "1", "csrf_token": token})
    assert response.status_code == 200
    assert response.json()["a"] == "1"


def test_cross_site_fetch_is_refused(unit_app):
    client = _client(unit_app)
    token = client.get("/_csrf").json()["token"]
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token, "Sec-Fetch-Site": "cross-site"}
    )
    assert response.status_code == 403


def test_token_is_stable_within_session_and_cookie_is_hardened(unit_app):
    client = _client(unit_app)
    first = client.get("/_csrf")
    second = client.get("/_csrf")
    assert first.json()["token"] == second.json()["token"]
    set_cookie = first.headers["set-cookie"]
    assert re.search(r"httponly", set_cookie, re.I)
    assert re.search(r"samesite=strict", set_cookie, re.I)
    assert "pgpp_session=" in set_cookie
    # the token itself is never written in the cookie in clear (signed payload)
    assert first.json()["token"] not in set_cookie


# --- token bound to the authenticated user (cookie tossing) -------------------

ALICE, BOB = "alice", "bob"


def _basic(user: str, password: str) -> dict[str, str]:
    import base64

    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _two_users_app(**overrides):
    from tests.conftest import TEST_HASH, add_probe_routes, create_app, make_settings

    app = create_app(
        make_settings(basic_users=f"{ALICE}:{TEST_HASH},{BOB}:{TEST_HASH}", **overrides)
    )
    add_probe_routes(app)

    @app.get("/_csrf")
    def csrf(request: Request) -> dict[str, str]:
        return {"token": get_csrf_token(request)}

    return app


def _two_users_client(**overrides):
    from fastapi.testclient import TestClient

    # no client.auth: the credentials are passed per request
    return TestClient(_two_users_app(**overrides))


def test_token_of_another_user_is_refused(unit_app):
    client = _two_users_client()
    response = client.get("/_csrf", headers=_basic(ALICE, TEST_PASSWORD))
    assert response.status_code == 200
    alice_token = response.json()["token"]
    alice = _basic(ALICE, TEST_PASSWORD)
    bob = _basic(BOB, TEST_PASSWORD)
    # the token works for alice herself
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": alice_token, **alice}
    )
    assert response.status_code == 200
    # alice's cookie (planted by a same-site page) + alice's token, bob's credentials
    response = client.post("/_echo", data={"a": "1"}, headers={"X-CSRF-Token": alice_token, **bob})
    assert response.status_code == 403, response.text
    # (the refusal rebinds the session to bob: alice's token is now void)
    assert (
        client.post("/_echo", data={"a": "1", "csrf_token": alice_token}, headers=bob).status_code
        == 403
    )
    assert (
        client.post("/_echo", data={"a": "1", "csrf_token": alice_token}, headers=alice).status_code
        == 403
    )


def test_anonymous_page_issues_no_token(unit_app):
    client = _two_users_client()
    response = client.get("/_whoami")
    assert response.status_code == 401
    # the 401 page (minimal, without base.html) carries no token and sets no
    # session cookie
    assert "set-cookie" not in response.headers
    assert re.search(r'<meta name="csrf-token"', response.text) is None
    assert not client.cookies
    # whatever was obtained anonymously (nothing) is refused with bob's credentials
    headers = {"X-CSRF-Token": "", **_basic(BOB, TEST_PASSWORD)}
    assert client.post("/_echo", data={"a": "1"}, headers=headers).status_code == 403


def test_first_login_after_anonymous_page(unit_app):
    client = _two_users_client()
    assert client.get("/_whoami").status_code == 401
    # same cookie jar, now authenticated: the token issued to bob is accepted
    token = client.get("/_csrf", headers=_basic(BOB, TEST_PASSWORD)).json()["token"]
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token, **_basic(BOB, TEST_PASSWORD)}
    )
    assert response.status_code == 200
    assert response.json() == {"a": "1"}
    # the token is regenerated as soon as the identity behind the cookie changes
    alice_token = client.get("/_csrf", headers=_basic(ALICE, TEST_PASSWORD)).json()["token"]
    assert alice_token != token
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token, **_basic(BOB, TEST_PASSWORD)}
    )
    assert response.status_code == 403


def test_same_site_fetch_is_refused(unit_app):
    client = _client(unit_app)
    token = client.get("/_csrf").json()["token"]
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token, "Sec-Fetch-Site": "same-site"}
    )
    assert response.status_code == 403
    response = client.post(
        "/_echo", data={"a": "1"}, headers={"X-CSRF-Token": token, "Sec-Fetch-Site": "same-origin"}
    )
    assert response.status_code == 200


def test_session_cookie_uses_host_prefix_when_secure():
    from fastapi.testclient import TestClient

    client = TestClient(_two_users_app(session_https_only=True), base_url="https://testserver")
    response = client.get("/_csrf", headers=_basic(ALICE, TEST_PASSWORD))
    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith("__Host-pgpp_session=")
    assert re.search(r"secure", set_cookie, re.I)
    assert re.search(r"path=/", set_cookie, re.I)
    assert not re.search(r"domain=", set_cookie, re.I)


def test_form_token_with_upper_case_content_type(unit_app):
    """Media types are case-insensitive: the form field is read whatever the case.

    (Without parameters only: python-multipart, used by Starlette to parse
    the body, does not lower-case a media type followed by "; charset=...",
    such a body is not read as a form at all and the request is refused.)"""
    client = _client(unit_app)
    token = client.get("/_csrf").json()["token"]
    for content_type in ("Application/X-WWW-Form-Urlencoded", "APPLICATION/X-WWW-FORM-URLENCODED"):
        response = client.post(
            "/_echo", content=f"a=1&csrf_token={token}", headers={"Content-Type": content_type}
        )
        assert response.status_code == 200, (content_type, response.text)
        assert response.json()["a"] == "1"
