"""Unit tests, seventeenth review round: user names in NFC form only (proxy
header and PGPP_WEB_BASIC_USERS), refused Unicode categories listed
explicitly, throttled warnings dated and flushed at shutdown, a single
peer expression in the log lines, the last known audit page."""

from __future__ import annotations

import base64
import logging
import subprocess
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

import bcrypt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import auth, main, usernames
from tests.conftest import add_probe_routes, make_settings
from tests.test_review_round15 import _proxy_client, _proxy_request


@pytest.fixture(autouse=True)
def _reset_throttles():
    for throttled in auth.THROTTLED_WARNINGS:
        throttled.reset()
    yield
    for throttled in auth.THROTTLED_WARNINGS:
        throttled.reset()


# --- 1: NFC form, no leading combining mark ------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("Émilie", "not in Unicode NFC form"),
        ("zoë", "not in Unicode NFC form"),
        ("́bob", "starts with a combining mark"),
        ("⃝x", "starts with a combining mark"),  # Me: enclosing mark
        ("ःx", "starts with a combining mark"),  # Mc: spacing mark
    ],
)
def test_decomposed_names_and_leading_marks_are_refused(name, reason):
    assert reason in usernames.user_name_problem(name)
    assert not auth._valid_user(name)
    response = _proxy_client().get("/_whoami", headers={"X-Remote-User": name.encode()})
    assert response.status_code == 401
    assert "not a valid user name" in response.text


def test_two_spellings_of_emilie_are_not_both_accepted():
    composed, decomposed = "\xc9milie", "Émilie"
    assert unicodedata.normalize("NFC", decomposed) == composed
    assert auth._valid_user(composed) and not auth._valid_user(decomposed)
    # refused, not normalised into the other one
    client = _proxy_client()
    assert client.get("/_whoami", headers={"X-Remote-User": composed.encode()}).json() == {
        "user": composed
    }
    assert client.get("/_whoami", headers={"X-Remote-User": decomposed.encode()}).status_code == 401


@pytest.mark.parametrize("name", ["\xc9milie", "é́"[:0] + "aé"[:1] + "b", "日本"])
def test_a_combining_mark_after_a_base_in_nfc_is_accepted(name):
    assert auth._valid_user(name)


def test_a_mark_without_precomposed_form_is_accepted():
    # q + combining acute: no precomposed character, already NFC
    name = "q́"
    assert unicodedata.is_normalized("NFC", name)
    assert auth._valid_user(name)


# --- 2: PGPP_WEB_BASIC_USERS under the same rule -----------------------------------------


_HASH = bcrypt.hashpw(b"pw", bcrypt.gensalt(rounds=4)).decode()


@pytest.mark.parametrize(
    ("user", "reason"),
    [
        ("Émilie", "not in Unicode NFC form"),
        ("́bob", "starts with a combining mark"),
        ("a\xa0b", "U+00A0 not allowed (category Zs)"),
        ("a​b", "U+200B not allowed (category Cf)"),
        ("ab", "U+E000 not allowed (category Co)"),
        ("x" * 129, "longer than 128 characters"),
    ],
)
def test_invalid_basic_user_names_are_refused_at_startup(user, reason):
    with pytest.raises(ValueError) as refused:
        make_settings(basic_users=f"{user}:{_HASH}")
    message = str(refused.value)
    assert f"PGPP_WEB_BASIC_USERS: user name {user!r} refused" in message
    assert reason in message


def test_valid_basic_user_names_are_accepted():
    settings = make_settings(basic_users=f"\xc9milie:{_HASH},a b:{_HASH},日本:{_HASH}")
    assert set(settings.basic_user_hashes()) == {"\xc9milie", "a b", "日本"}


def test_config_does_not_import_auth():
    # the rule lives in app.usernames, importable by config.py without a cycle
    import app.config as config

    assert config.user_name_problem is usernames.user_name_problem
    code = "import sys, app.config; assert 'app.auth' not in sys.modules, sorted(sys.modules)"
    subprocess.run([sys.executable, "-c", code], check=True, cwd=Path(__file__).parents[1])


# --- 3: explicit refused categories ---------------------------------------------------------


def test_refused_categories_are_listed():
    assert usernames.REFUSED_CATEGORIES == {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"}


@pytest.mark.parametrize(
    "char",
    ["\x00", "\x85", "­", "‮", "\ud800", "", "\U000f0000", " ", " "] + ["\xa0", " ", "　"],
)
def test_each_refused_category_is_refused(char):
    assert unicodedata.category(char) in usernames.REFUSED_CATEGORIES
    assert not auth._valid_user(f"a{char}b")


def test_unassigned_code_points_are_refused():
    # U+0378 is unassigned (Cn) in every Unicode version so far
    assert unicodedata.category("͸") == "Cn"
    assert "category Cn" in usernames.user_name_problem("a͸b")


def test_the_ascii_space_is_accepted_inside_only():
    assert auth._valid_user("a b")
    assert not auth._valid_user(" ab") and not auth._valid_user("ab ")


# --- 4: throttled warnings dated, flushed at shutdown --------------------------------------


def _clock(monkeypatch, start: float = 1000.0) -> list[float]:
    clock = [start]
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock[0])
    return clock


def test_the_suppressed_count_is_dated_from_the_first_suppression(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    clock = _clock(monkeypatch)
    stamps = iter(
        [datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), datetime(2026, 1, 2, 3, 9, 0, tzinfo=UTC)]
    )
    monkeypatch.setattr(auth, "_utcnow", lambda: next(stamps))
    throttled = auth._ThrottledWarning("probe", 60.0)
    throttled.warning("w %s", 1)
    for _ in range(3):
        clock[0] += 5
        throttled.warning("w %s", 2)
    clock[0] += 60
    throttled.warning("w %s", 3)
    assert [r.getMessage() for r in caplog.records] == [
        "w 1",
        "w 3 (3 similar warnings suppressed since 2026-01-02T03:04:05+00:00)",
    ]
    # a new window, a new date
    caplog.clear()
    clock[0] += 1
    throttled.warning("w %s", 4)
    throttled.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "probe: 1 similar warnings suppressed since 2026-01-02T03:09:00+00:00"
    ]


def test_flush_is_silent_without_suppressed_warnings(caplog):
    caplog.set_level(logging.WARNING)
    throttled = auth._ThrottledWarning("probe")
    throttled.flush()
    throttled.warning("once")
    throttled.flush()
    assert [r.getMessage() for r in caplog.records] == ["once"]
    # flushed counts are not reported twice
    caplog.clear()
    throttled.flush()
    assert not caplog.records


class _Pool:
    def __init__(self):
        self.closed = False

    def open(self, wait=False):
        pass

    def close(self):
        self.closed = True


def test_suppressed_warnings_are_flushed_at_shutdown(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    monkeypatch.setattr(auth, "_utcnow", lambda: datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC))
    pool = _Pool()
    monkeypatch.setattr(main, "make_pool", lambda settings: pool)
    app = main.create_app(make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User"))
    add_probe_routes(app)
    with TestClient(app, client=("192.168.1.9", 40000)) as client:
        for _ in range(3):
            assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == 403
        assert len(caplog.records) == 1
    assert pool.closed
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9",
        "proxy header refused from untrusted peer: 2 similar warnings suppressed"
        " since 2026-05-06T07:08:09+00:00",
    ]


# --- 5: untrusted peer warning throttled -----------------------------------------------------


def test_the_untrusted_peer_warning_is_throttled(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    app = main.create_app(make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User"))
    add_probe_routes(app)
    client = TestClient(app, client=("192.168.1.9", 40000))
    for _ in range(10):
        assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == 403
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9"
    ]
    # distinct from the undecodable header throttle
    assert auth._untrusted_proxy_peer is not auth._undecodable_proxy_header


# --- 6: a single peer expression -------------------------------------------------------------


def _request_with_client(client):
    request = _proxy_request(b"carol")
    request.scope["client"] = client
    return request


@pytest.mark.parametrize(
    ("client", "peer"),
    [(("10.0.0.1", 1), "10.0.0.1"), (None, "unix"), (("", 0), "unix")],
)
def test_peer(client, peer):
    assert auth._peer(_request_with_client(client)) == peer


def test_basic_failure_from_a_unix_peer_with_an_empty_host_logs_unix(caplog):
    # the former expression logged an empty host here
    caplog.set_level(logging.WARNING)
    settings = make_settings()
    request = _request_with_client(("", 0))
    request.scope["headers"] = [(b"authorization", b"Basic " + base64.b64encode(b"x:y"))]
    request.scope["session"] = {}
    request.scope["app"] = type("A", (), {"state": type("S", (), {"settings": settings})()})()
    with pytest.raises(HTTPException) as refused:
        auth.require_user(request)
    assert refused.value.status_code == 401
    assert "basic authentication failed for user x from unix" in caplog.text


# --- 8: last known audit page ------------------------------------------------------------


def _past_end_table(last_known_page) -> str:
    from app.templating import templates

    template = templates.env.get_template("audit/_table.html")
    return template.render(
        path_for=lambda name: f"/{name}",
        filters={"role": "", "type": "", "since": ""},
        total=10_001,
        total_label="10,000+",
        events=[],
        past_end=True,
        last_known_page=last_known_page,
        page=700,
        pages=None,
        has_next=False,
        error=None,
    )


@pytest.mark.parametrize("last_known_page", [None, 1])
def test_no_last_known_page_named_without_its_link(last_known_page):
    html = _past_end_table(last_known_page)
    assert "the last page is not known)." in html
    assert "last one known" not in html and "Last known page" not in html
    assert "First page" in html


def test_the_last_known_page_is_named_with_its_link():
    html = _past_end_table(201)
    assert "page 201 is the last one known to hold events" in html
    assert "Last known page (201)" in html
