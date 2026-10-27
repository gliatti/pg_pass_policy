import pytest

from tests.conftest import TEST_HASH, make_settings


def test_short_secret_rejected():
    with pytest.raises(ValueError, match="at least 32"):
        make_settings(secret="short")


def test_basic_requires_users():
    with pytest.raises(ValueError, match="BASIC_USERS"):
        make_settings(basic_users="")


def test_basic_users_parsing():
    settings = make_settings(basic_users=f" alice:{TEST_HASH} , bob:{TEST_HASH}")
    assert set(settings.basic_user_hashes()) == {"alice", "bob"}


def test_basic_users_must_be_bcrypt():
    with pytest.raises(ValueError, match="bcrypt"):
        make_settings(basic_users="alice:plaintext")


def test_proxy_mode_needs_no_users():
    settings = make_settings(auth="proxy", basic_users="", proxy_header="REMOTE_USER")
    assert settings.proxy_header_name() == "remote-user"
    assert [str(n) for n in settings.trusted_networks()] == ["127.0.0.1/32", "::1/128"]


def test_trusted_proxies_syntax():
    with pytest.raises(ValueError):
        make_settings(trusted_proxies="not-an-ip")
    settings = make_settings(trusted_proxies="10.0.0.0/8, unix")
    assert settings.trust_unix_peer()
    assert not settings.trust_all_proxies()
