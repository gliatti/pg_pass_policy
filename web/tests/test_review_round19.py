"""Unit tests, nineteenth review round: throttling keyed by the normalised
peer address and capped for all keys together, claimed user names always
logged escaped and quoted, refused proxy user names logged (throttled),
the user name rule built from its constants, no invisible code point
already refused by NFKC."""

from __future__ import annotations

import logging
import unicodedata
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import auth, main, usernames
from tests.conftest import add_probe_routes, make_settings
from tests.test_review_round15 import _proxy_request


def _clock(monkeypatch, start: float = 1000.0) -> list[float]:
    clock = [start]
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock[0])
    return clock


def _fixed_now(monkeypatch):
    monkeypatch.setattr(auth, "_utcnow", lambda: datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC))


def _proxy_app():
    app = main.create_app(make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User"))
    add_probe_routes(app)
    return app


# --- 1: the key is the normalised peer address ---------------------------------------------


@pytest.mark.parametrize(
    ("host", "key"),
    [
        ("::ffff:192.168.1.9", "192.168.1.9"),
        ("192.168.1.9", "192.168.1.9"),
        ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:bbbb::2", "2001:db8:1:2::/64"),
        ("not-an-address", "not-an-address"),
    ],
)
def test_the_peer_key_is_normalised(host, key):
    request = _proxy_request(b"carol")
    request.scope["client"] = (host, 1)
    assert auth._peer_key(request) == key


def test_unix_peer_key():
    request = _proxy_request(b"carol")
    request.scope["client"] = None
    assert auth._peer_key(request) == "unix"


def test_one_ipv6_64_shares_one_window(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    app = _proxy_app()
    for i in range(1, 6):
        client = TestClient(app, client=(f"2001:db8:1:2::{i:x}", 40000))
        assert client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code == 403
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 2001:db8:1:2::1"
    ]
    assert list(app.state.auth_warnings.untrusted_proxy_peer._windows) == ["2001:db8:1:2::/64"]


# --- 7: a global cap, all keys together -----------------------------------------------------


def test_the_lines_are_capped_for_all_keys(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    clock = _clock(monkeypatch)
    _fixed_now(monkeypatch)
    throttled = auth._ThrottledWarning("probe", max_lines=3)
    for i in range(10):
        throttled.warning("w %s", i, key=str(i))
    assert [r.getMessage() for r in caplog.records] == ["w 0", "w 1", "w 2"]
    caplog.clear()
    # the next interval: the global count first, then the warning
    clock[0] += 60
    throttled.warning("w %s", 10, key="10")
    assert [r.getMessage() for r in caplog.records] == [
        "probe (all sources): 7 similar warnings suppressed since 2026-05-06T07:08:09+00:00",
        "w 10",
    ]
    caplog.clear()
    # reported once
    throttled.flush()
    assert not caplog.records


def test_the_global_count_is_flushed_at_shutdown(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    throttled = auth._ThrottledWarning("probe", max_lines=1)
    throttled.warning("w", key="a")
    throttled.warning("w", key="a")  # per key
    throttled.warning("w", key="b")  # global
    throttled.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "w",
        "probe a: 1 similar warnings suppressed since 2026-05-06T07:08:09+00:00",
        "probe (all sources): 1 similar warnings suppressed since 2026-05-06T07:08:09+00:00",
    ]


def test_a_scan_of_many_peers_writes_at_most_the_cap(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    warnings = auth.AuthWarnings()
    throttled = warnings.untrusted_proxy_peer
    assert throttled.max_lines == auth.MAX_LINES_PER_INTERVAL == 20
    for i in range(1000):
        throttled.warning("w", key=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}")
    # the evicted keys had nothing pending: one line each for the first 20
    assert len(caplog.records) == 20
    caplog.clear()
    warnings.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer (all sources):"
        " 980 similar warnings suppressed since 2026-05-06T07:08:09+00:00"
    ]


# --- 2+4: the claimed name always escaped and quoted ----------------------------------------


@pytest.mark.parametrize(
    "name",
    ["alice", "x from 10.6.6.6", "x' from 10.6.6.6", 'x" from 10.6.6.6', "a\nb", "Émilie"],
)
def test_a_claimed_name_is_always_quoted(name):
    logged = auth._loggable(name)
    assert logged == ascii(name)
    assert logged.isascii()
    assert logged[0] in "'\"" and logged[-1] == logged[0]


def test_a_long_name_is_cut_before_escaping():
    name = "​" * 200
    logged = auth._loggable(name)
    assert logged == ascii("​" * 128) + "…"


def test_a_name_cannot_forge_the_peer_in_the_basic_failure_line(unit_client, caplog):
    import base64

    caplog.set_level(logging.WARNING)
    header = "Basic " + base64.b64encode(b"x from 10.6.6.6:pw").decode()
    assert unit_client.get("/_whoami", headers={"Authorization": header}).status_code == 401
    assert "basic authentication failed for user 'x from 10.6.6.6' from testclient" in caplog.text


# --- 3: a refused proxy user name is logged, throttled per peer ------------------------------


def test_a_refused_proxy_name_is_logged_with_its_reason(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    warnings = auth.AuthWarnings()
    settings = make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User")
    for _ in range(3):
        with pytest.raises(HTTPException) as refused:
            auth.user_from_proxy(_proxy_request("bob️".encode(), warnings), settings)
        assert refused.value.status_code == 401
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header user name 'bob\\ufe0f' refused from peer 127.0.0.1:"
        " character U+FE0F not allowed (invisible)"
    ]
    caplog.clear()
    warnings.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header user name refused from peer 127.0.0.1:"
        " 2 similar warnings suppressed since 2026-05-06T07:08:09+00:00"
    ]
    assert warnings.refused_proxy_user in warnings.all()


# --- 5: the rule is built from its constants ------------------------------------------------


def test_the_rule_quotes_the_constants():
    rule = usernames.USER_NAME_RULE
    assert f"1 to {usernames.USER_MAX_LENGTH} characters" in rule
    assert " ".join(sorted(usernames.REFUSED_CATEGORIES)) in rule
    assert f"{len(usernames.INVISIBLE_CODE_POINTS)} invisible code points" in rule


# --- 6: no invisible code point already refused by NFKC ----------------------------------------


def test_no_invisible_code_point_is_refused_by_nfkc():
    for code_point in usernames.INVISIBLE_CODE_POINTS:
        assert unicodedata.is_normalized("NFKC", chr(code_point)), f"U+{code_point:04X}"


@pytest.mark.parametrize("code_point", [0x3164, 0xFFA0])
def test_the_hangul_fillers_are_refused_by_nfkc(code_point):
    assert code_point not in usernames.INVISIBLE_CODE_POINTS
    assert "not in Unicode NFKC form" in usernames.user_name_problem(f"bob{chr(code_point)}")
