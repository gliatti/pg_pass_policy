"""Unit tests, eighteenth review round: untrusted peer warnings throttled per
peer (bounded, least recently seen dropped), throttled warnings owned by
the application, invisible code points and compatibility forms (NFKC)
refused in user names, refused names logged in ASCII, the startup error
on PGPP_WEB_BASIC_USERS naming the rule."""

from __future__ import annotations

import logging
import unicodedata
from datetime import UTC, datetime

import bcrypt
import pytest
from fastapi.testclient import TestClient

from app import auth, main, usernames
from tests.conftest import add_probe_routes, make_settings
from tests.test_review_round15 import _proxy_client


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


def _untrusted(app, host: str) -> int:
    client = TestClient(app, client=(host, 40000))
    return client.get("/_whoami", headers={"X-Remote-User": "carol"}).status_code


# --- 3: one window per peer --------------------------------------------------------------


def test_untrusted_peer_warnings_are_throttled_per_peer(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    clock = _clock(monkeypatch)
    _fixed_now(monkeypatch)
    app = _proxy_app()
    for _ in range(3):
        for host in ("192.168.1.9", "192.168.1.10"):
            assert _untrusted(app, host) == 403
    # one line per peer: the noisy first address does not hide the second
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9",
        "proxy header refused from untrusted peer 192.168.1.10",
    ]
    caplog.clear()
    clock[0] += 60
    assert _untrusted(app, "192.168.1.10") == 403
    # the count suppressed for that peer only
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.10"
        " (2 similar warnings suppressed since 2026-05-06T07:08:09+00:00)"
    ]
    caplog.clear()
    app.state.auth_warnings.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9:"
        " 2 similar warnings suppressed since 2026-05-06T07:08:09+00:00"
    ]


def test_the_peers_tracked_are_bounded_least_recently_seen_dropped(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    throttled = auth._ThrottledWarning("probe", max_keys=2)
    for key in ("a", "a", "b", "a"):
        throttled.warning("w %s", key, key=key)
    assert [r.getMessage() for r in caplog.records] == ["w a", "w b"]
    caplog.clear()
    # a third key drops the least recently seen one ("b"), nothing pending
    throttled.warning("w %s", "c", key="c")
    assert list(throttled._windows) == ["a", "c"]
    assert [r.getMessage() for r in caplog.records] == ["w c"]
    caplog.clear()
    # a fourth key drops "a": its pending count goes to the global count,
    # not lost, without a line of its own
    throttled.warning("w %s", "d", key="d")
    assert list(throttled._windows) == ["c", "d"]
    assert [r.getMessage() for r in caplog.records] == ["w d"]
    caplog.clear()
    throttled.flush()
    assert [r.getMessage() for r in caplog.records] == [
        "probe (all sources): 2 similar warnings suppressed since 2026-05-06T07:08:09+00:00",
    ]


def test_the_default_bound_is_256_peers(monkeypatch):
    _clock(monkeypatch)
    warnings = auth.AuthWarnings()
    assert warnings.untrusted_proxy_peer.max_keys == auth.UNTRUSTED_PEERS_TRACKED == 256
    for i in range(300):
        warnings.untrusted_proxy_peer.warning("w", key=f"10.0.{i // 256}.{i % 256}")
    assert len(warnings.untrusted_proxy_peer._windows) == 256


# --- 8: the throttled warnings belong to the application ---------------------------------


class _Pool:
    def open(self, wait=False):
        pass

    def close(self):
        pass


def test_each_application_has_its_own_throttled_warnings(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _clock(monkeypatch)
    _fixed_now(monkeypatch)
    monkeypatch.setattr(main, "make_pool", lambda settings: _Pool())
    first, second = _proxy_app(), _proxy_app()
    assert first.state.auth_warnings is not second.state.auth_warnings
    assert not hasattr(auth, "THROTTLED_WARNINGS")
    for _ in range(3):
        assert _untrusted(first, "192.168.1.9") == 403
    # the other application has its own window: logged, not suppressed
    assert _untrusted(second, "192.168.1.9") == 403
    assert _untrusted(second, "192.168.1.9") == 403
    assert len(caplog.records) == 2
    caplog.clear()
    # the shutdown of the second application flushes its own count only
    with TestClient(second):
        pass
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9:"
        " 1 similar warnings suppressed since 2026-05-06T07:08:09+00:00"
    ]
    caplog.clear()
    with TestClient(first):
        pass
    assert [r.getMessage() for r in caplog.records] == [
        "proxy header refused from untrusted peer 192.168.1.9:"
        " 2 similar warnings suppressed since 2026-05-06T07:08:09+00:00"
    ]


# --- 5: invisible code points --------------------------------------------------------------

_INVISIBLE = [
    0xFE00,
    0xFE0F,
    0xE0100,
    0xE01EF,
    0x034F,
    0x180B,
    0x180C,
    0x180D,
    0x180F,
    0x115F,
    0x1160,
    0x2800,
    0x17B4,
    0x17B5,
]


@pytest.mark.parametrize("code_point", _INVISIBLE, ids=lambda c: f"U+{c:04X}")
def test_invisible_code_points_are_refused(code_point):
    char = chr(code_point)
    # outside the refused categories: refused by the explicit list
    assert unicodedata.category(char) not in usernames.REFUSED_CATEGORIES
    assert code_point in usernames.INVISIBLE_CODE_POINTS
    name = f"bob{char}"
    problem = usernames.user_name_problem(name)
    assert problem is not None
    assert not auth._valid_user(name)
    response = _proxy_client().get("/_whoami", headers={"X-Remote-User": name.encode()})
    assert response.status_code == 401
    assert "not a valid user name" in response.text


def test_the_invisible_list_holds_the_ranges():
    expected = (
        {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800}
        | set(range(0x180B, 0x1810))
        | set(range(0xFE00, 0xFE10))
        | set(range(0xE0100, 0xE01F0))
    )
    assert usernames.INVISIBLE_CODE_POINTS == expected
    assert "U+FE0F not allowed (invisible)" in usernames.user_name_problem("a️")


# --- 6: compatibility forms (NFKC) ---------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ａｌｉｃｅ",  # fullwidth alice
        "ﬁlip",  # ligature fi
        "\U0001d41a\U0001d425\U0001d422\U0001d41c\U0001d41e",  # mathematical bold alice
        "bob²",  # superscript two
        "Ⅰ",  # roman numeral one
    ],
)
def test_compatibility_forms_are_refused(name):
    assert unicodedata.is_normalized("NFC", name)
    assert "not in Unicode NFKC form" in usernames.user_name_problem(name)
    response = _proxy_client().get("/_whoami", headers={"X-Remote-User": name.encode()})
    assert response.status_code == 401


@pytest.mark.parametrize("name", ["\xc9milie", "zo\xeb", "a b", "日本", "q́"])
def test_plain_names_are_still_accepted(name):
    assert usernames.user_name_problem(name) is None


# --- 7: refused names logged in ASCII -------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["Émilie", "a​b", "bob️", "ａ", "‮alice", "x" * 200 + "\xe9"],
)
def test_a_refused_name_is_logged_in_ascii(name):
    logged = auth._loggable(name)
    if len(name) > 128:
        # cut before escaping, then marked as cut
        assert logged == ascii(name[:128]) + "…"
    else:
        assert logged == ascii(name)
        assert logged.isascii()


# --- 4: the startup error names the escaped name, the reason and the rule ----------------


def test_a_refused_basic_user_names_the_rule():
    digest = bcrypt.hashpw(b"pw", bcrypt.gensalt(rounds=4)).decode()
    with pytest.raises(ValueError) as refused:
        make_settings(basic_users=f"bob​:{digest}")
    message = str(refused.value)
    assert message.isascii()
    assert "user name 'bob\\u200b' refused" in message
    assert "character U+200B not allowed (category Cf)" in message
    assert usernames.USER_NAME_RULE in message
