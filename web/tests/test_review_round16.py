"""Unit tests, sixteenth review round: proxy header encoding set explicitly
(PGPP_WEB_PROXY_HEADER_ENCODING, strict decoding), a page past a capped
audit shown as such, the Basic header decoded once per request."""

from __future__ import annotations

import base64
import inspect
import logging
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import auth, db
from tests.conftest import TEST_PASSWORD, TEST_USER, make_settings
from tests.test_review_round6 import _client
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)
from tests.test_review_round15 import _proxy_request

# --- 1-4: proxy header encoding ------------------------------------------------------------


def _proxy_settings(**kw):
    return make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User", **kw)


def test_the_proxy_header_encoding_defaults_to_utf8():
    assert _proxy_settings().proxy_header_encoding == "utf-8"


@pytest.mark.parametrize(("value", "expected"), [("UTF-8", "utf-8"), (" Latin-1 ", "latin-1")])
def test_the_proxy_header_encoding_is_normalised(value, expected):
    assert _proxy_settings(proxy_header_encoding=value).proxy_header_encoding == expected


@pytest.mark.parametrize("value", ["utf8", "latin1", "ascii", "cp1252", ""])
def test_an_unknown_proxy_header_encoding_is_refused(value):
    with pytest.raises(ValueError, match="PGPP_WEB_PROXY_HEADER_ENCODING must be utf-8 or latin-1"):
        _proxy_settings(proxy_header_encoding=value)


def _refused(raw: bytes, settings) -> HTTPException:
    with pytest.raises(HTTPException) as refused:
        auth.user_from_proxy(_proxy_request(raw), settings)
    assert refused.value.status_code == 401
    return refused.value


@pytest.fixture(autouse=True)
def _reset_throttle():
    auth._undecodable_proxy_header.reset()
    yield
    auth._undecodable_proxy_header.reset()


@pytest.mark.parametrize("raw", [b"\xc9milie", b"bad\xff", b"\xe2\x82"])
def test_a_proxy_header_not_valid_utf8_is_refused(raw, caplog):
    caplog.set_level(logging.DEBUG)
    error = _refused(raw, _proxy_settings())
    assert error.detail == "Not authenticated (proxy header not valid utf-8)"
    # no fallback to another encoding; one warning, without the header content
    assert "latin-1" not in caplog.text
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert record.getMessage() == (
        f"proxy header x-remote-user not valid utf-8 ({len(raw)} bytes) from 127.0.0.1"
    )
    assert raw.decode("latin-1") not in caplog.text and repr(raw) not in caplog.text


def test_undecodable_proxy_headers_are_logged_once_per_minute(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    clock = [1000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock[0])
    first_suppressed = datetime(2026, 10, 28, 9, 30, 5, tzinfo=UTC)
    wall = iter([first_suppressed, first_suppressed.replace(second=59)])
    monkeypatch.setattr(auth, "_utcnow", lambda: next(wall))
    settings = _proxy_settings()
    for _ in range(5):
        _refused(b"bad\xff", settings)
        clock[0] += 10
    # the first one only, within 60 s
    assert len(caplog.records) == 1
    caplog.clear()
    clock[0] = 1000.0 + 60
    _refused(b"\xc9milie", settings)
    [record] = caplog.records
    assert record.getMessage() == (
        "proxy header x-remote-user not valid utf-8 (6 bytes) from 127.0.0.1"
        " (4 similar warnings suppressed since 2026-10-28T09:30:05+00:00)"
    )
    # a valid header is not affected and does not log
    caplog.clear()
    assert auth.user_from_proxy(_proxy_request(b"carol"), settings) == "carol"
    assert not caplog.records


# Unicode spaces and NEL: neither stripped nor accepted, in either encoding,
# so that "bob" comes from the byte sequence b"bob" only
_UNICODE_BLANKS = {
    "utf-8": [
        ("bob\xa0".encode(), "not a valid user name"),
        ("\xa0bob".encode(), "not a valid user name"),
        ("bob\u3000".encode(), "not a valid user name"),
        ("\u3000bob".encode(), "not a valid user name"),
        ("bob\x85".encode(), "not a valid user name"),
        ("b\u3000ob".encode(), "not a valid user name"),
        # the latin-1 bytes of NBSP and NEL are not UTF-8
        (b"bob\xa0", "not valid utf-8"),
        (b"bob\x85", "not valid utf-8"),
    ],
    "latin-1": [
        (b"bob\xa0", "not a valid user name"),
        (b"\xa0bob", "not a valid user name"),
        (b"bob\x85", "not a valid user name"),
        (b"\x85bob", "not a valid user name"),
        # U+3000 has no latin-1 form: its UTF-8 bytes read as latin-1 end
        # with C1 controls
        ("bob\u3000".encode(), "not a valid user name"),
        ("bob\xa0".encode(), "not a valid user name"),
    ],
}


@pytest.mark.parametrize(
    ("encoding", "raw", "reason"),
    [(enc, raw, reason) for enc, cases in _UNICODE_BLANKS.items() for raw, reason in cases],
)
def test_unicode_blanks_are_not_stripped_but_refused(encoding, raw, reason):
    settings = _proxy_settings(proxy_header_encoding=encoding)
    assert _refused(raw, settings).detail == f"Not authenticated (proxy header {reason})"
    assert auth.user_from_proxy(_proxy_request(b" bob\t"), settings) == "bob"


def test_utf8_names_are_decoded_strictly():
    settings = _proxy_settings()
    for name in ["Émilie", "à", "日本", "carol"]:
        # "à" is C3 A0: the A0 byte must not be stripped as a blank
        assert auth.user_from_proxy(_proxy_request(name.encode()), settings) == name
    assert auth.user_from_proxy(_proxy_request(b"  carol \t"), settings) == "carol"


def test_latin1_proxy_header():
    settings = _proxy_settings(proxy_header_encoding="latin-1")
    assert auth.user_from_proxy(_proxy_request(b"\xc9milie"), settings) == "Émilie"
    # the UTF-8 bytes of "Émilie" are read as latin-1: "Ã" then a C1 control
    error = _refused("Émilie".encode(), settings)
    assert error.detail == "Not authenticated (proxy header not a valid user name)"


def test_a_missing_proxy_header_is_reported_as_missing():
    settings = _proxy_settings()
    for raw in [b"", b"   "]:
        assert _refused(raw, settings).detail == "Not authenticated (proxy header missing)"
    assert _refused(b"a\x01b", settings).detail == (
        "Not authenticated (proxy header not a valid user name)"
    )


# --- 6: a page past a capped audit ---------------------------------------------------------


def test_a_stale_link_past_a_capped_audit_is_shown_empty(app, monkeypatch):  # noqa: F811
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        # 25,000 events, counted up to the cap
        seen.append(offset)
        rows = [{"id": 1, "event_type": "auth_failed"}] if offset < 25_000 else []
        return db.AuditPage(rows, db.AUDIT_COUNT_CAP + 1, capped=True, has_next=bool(rows))

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _client(app)
    response = client.get("/audit/table", params={"page": "700"})
    assert response.status_code == 200
    # one query, no page presented as the last one
    assert seen == [699 * 50]
    assert "10,000+ events — page 700</p>" in response.text
    assert "Page 700 is past the end of the matching events" in response.text
    assert "the last page is not known" in response.text
    assert "&page=1" in response.text and "First page" in response.text
    # and a link to the last page known to exist: the one holding event
    # AUDIT_COUNT_CAP + 1 (50 events per page)
    assert "page 201 is the last one known to hold events" in response.text
    assert "&page=201" in response.text and "Last known page (201)" in response.text
    # no pager (its "previous" would lead to another empty page)
    assert 'class="pager"' not in response.text
    assert "&page=699" not in response.text and "&page=701" not in response.text
    # the link leads to a page with events
    response = client.get("/audit/table", params={"page": "201"})
    assert seen[-1] == 200 * 50 and "past the end" not in response.text

    # a page beyond the cap that has events is shown as such
    response = client.get("/audit/table", params={"page": "400"})
    assert seen[-1] == 399 * 50
    assert "past the end" not in response.text
    assert "&page=399" in response.text and "&page=401" in response.text


def test_a_stale_link_past_an_uncapped_audit_shows_the_last_page(app, monkeypatch):  # noqa: F811
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        seen.append(offset)
        rows = [{"id": 1, "event_type": "auth_failed"}] if offset < 120 else []
        return db.AuditPage(rows, 120, has_next=offset + limit < 120)

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _client(app)
    response = client.get("/audit/table", params={"page": "9"})
    assert seen == [8 * 50, 2 * 50]
    assert "120 events — page 3 / 3</p>" in response.text
    assert "past the end" not in response.text


# --- 7-9: the Basic header is decoded once -------------------------------------------------


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_a_failed_basic_check_decodes_the_header_once(unit_app, monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    decodes: list[str | None] = []
    real_decode = auth._decode_basic

    def counting_decode(authorization):
        decodes.append(authorization)
        return real_decode(authorization)

    monkeypatch.setattr(auth, "_decode_basic", counting_decode)
    client = TestClient(unit_app)
    bad = {"Authorization": _basic(TEST_USER, "wrong-password")}
    assert client.get("/_whoami", headers=bad).status_code == 401
    assert len(decodes) == 1
    assert f"basic authentication failed for user {TEST_USER} from" in caplog.text
    # a malformed header: logged without a user name, decoded once as well
    decodes.clear()
    assert client.get("/_whoami", headers={"Authorization": "Basic !!!"}).status_code == 401
    assert len(decodes) == 1
    assert "basic authentication failed for user <none> from" in caplog.text
    good = {"Authorization": _basic(TEST_USER, TEST_PASSWORD)}
    assert client.get("/_whoami", headers=good).json() == {"user": TEST_USER}


def test_cached_basic_user_requires_the_claimed_name():
    claimed = inspect.signature(auth._cached_basic_user).parameters["claimed"]
    assert claimed.default is inspect.Parameter.empty


def test_authenticate_basic_without_a_header():
    from types import SimpleNamespace

    session = {auth.SESSION_BASIC_KEY: {"user": TEST_USER, "fp": "x"}}
    request = SimpleNamespace(headers={}, session=session)
    assert auth.authenticate_basic(request, make_settings()) == auth.BasicResult(None, None)
    assert auth.SESSION_BASIC_KEY not in session
