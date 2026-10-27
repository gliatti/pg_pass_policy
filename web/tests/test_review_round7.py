"""Unit tests, seventh review round: log masking keeps the access lines,
worker_status() and the "not preloaded" page, empty switch result, static
URLs versioned, masking run once per record, one htmx detection, full page
for a non-htmx profile delete, shared one-time password response."""

from __future__ import annotations

import hashlib
import inspect
import io
import logging
import re
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi import Request
from uvicorn.logging import AccessFormatter

from app import db, logfilter
from app.logfilter import MASK, PasswordMaskFilter, install_log_masking
from app.main import create_app
from app.routers import pairs, roles
from app.templating import STATIC_DIR, is_hx, reveal_response
from tests.conftest import make_settings
from tests.test_review_round6 import (
    HINT,
    FakeConn,
    NotPreloaded,
    _client,
    _raise,
)
from tests.test_review_round6 import (
    app as app,  # noqa: F401 (fixture)
)

ACCESS_TEMPLATE = '%s - "%s %s HTTP/%s" %d'


def _access_line(*args) -> tuple[str, logging.LogRecord]:
    """Log one access line the way uvicorn does (five arguments), formatted
    by uvicorn's own AccessFormatter."""
    install_log_masking()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
    )
    records: list[logging.LogRecord] = []
    handler.addFilter(lambda record: records.append(record) or True)
    logger = logging.getLogger("pgpp_web.test.access")
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        logger.info(ACCESS_TEMPLATE, *args)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)
    return stream.getvalue(), records[0]


# --- 1: the access line survives a match on the joined message --------------------------


def test_access_line_kept_when_only_the_joined_message_matches():
    """ "token:" ends the path, the HTTP version follows once joined: the
    masked message replaces the template, the five arguments stay."""
    line, record = _access_line("127.0.0.1:5000", "GET", "/audit?role=token:", "1.1", 200)
    assert line == '127.0.0.1:5000 - "GET /audit?role=token: HTTP/1.1" 200 OK\n'
    assert len(record.args) == 5 and record.args[4] == 200
    assert record.getMessage() == f'127.0.0.1:5000 - "GET /audit?role=token: {MASK}" 200'


def test_access_line_with_a_secret_in_the_path():
    line, record = _access_line("127.0.0.1:5000", "GET", "/x?password=Hunter2", "1.1", 404)
    assert "Hunter2" not in line and "Hunter2" not in record.getMessage()
    assert line == f'127.0.0.1:5000 - "GET /x?password={MASK} HTTP/1.1" 404 Not Found\n'


def test_joined_template_keeps_its_percent_signs():
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "100%% done, password=%s", ("Hunter2",), None
    )
    assert PasswordMaskFilter().filter(record)
    # the argument alone is no secret: kept, it formats to nothing
    assert record.args == ("Hunter2",)
    assert record.getMessage() == f"100% done, password={MASK}"


def test_mapping_args_still_format():
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "password=%(p)s", ({"p": "Hunter2"},), None
    )
    assert isinstance(record.args, dict)
    assert PasswordMaskFilter().filter(record)
    assert record.getMessage() == f"password={MASK}"


# --- 2: worker_status() and the "not preloaded" page -------------------------------------


class _NoShmemConn(FakeConn):
    def execute(self, *args, **kwargs):
        raise NotPreloaded()


def test_maintenance_without_preload_is_the_dedicated_page(app, caplog):  # noqa: F811
    caplog.set_level(logging.ERROR)
    conn = _NoShmemConn([])
    app.dependency_overrides[db.get_conn] = lambda: conn
    client, _ = _client(app)
    response = client.get("/maintenance")
    assert response.status_code == 503
    assert "pg_pass_policy is not preloaded</h1>" in response.text
    assert HINT in response.text
    assert conn.events == ["savepoint", "rollback"]


# --- 3: switch_rotation_pair() returning no row --------------------------------------------


def test_switch_without_a_row_is_a_warning(app, monkeypatch, caplog):  # noqa: F811
    """FakeConn's fetchone() returns None: no TypeError (500) after the commit."""
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(db, "list_pairs", lambda conn: [])
    client, token = _client(app)
    response = client.post(
        "/pairs/p1/switch", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert "Pair p1: the switch was applied but returned no row" in response.text
    assert "again" not in response.text
    assert 'class="secret"' not in response.text
    assert "pair p1: switch applied but no row returned" in caplog.text
    assert "commit" in app.state.pool.events


# --- 4: versioned static URLs --------------------------------------------------------------


def test_static_urls_carry_a_content_version(app):  # noqa: F811
    client, _ = _client(app)
    response = client.get("/maintenance")  # extends base.html (FakeConn: no worker)
    assert response.status_code == 200
    for name in ("app.css", "app.js", "htmx.min.js"):
        version = hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:12]
        assert f'"/static/{name}?v={version}"' in response.text
    match = re.search(r'href="(/static/app\.css\?v=[0-9a-f]+)"', response.text)
    assert match
    static = client.get(match.group(1))
    assert static.status_code == 200
    assert static.headers["Cache-Control"] == "public, max-age=3600"


# --- 5: masking runs once per record ----------------------------------------------------


def test_masking_runs_once_per_record(monkeypatch):
    create_app(make_settings())
    calls = []
    real = logfilter._FILTER.mask_message

    def spy(record, **kwargs):
        calls.append(record)
        return real(record, **kwargs)

    monkeypatch.setattr(logfilter._FILTER, "mask_message", spy)
    for name in (None, "uvicorn", "uvicorn.access", "uvicorn.error", "pgpp_web", "pgpp_web.x"):
        logger = logging.getLogger(name)
        assert not any(isinstance(f, PasswordMaskFilter) for f in logger.filters)
        for handler in logger.handlers:
            assert not any(isinstance(f, PasswordMaskFilter) for f in handler.filters)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s [%(new_password)s]"))
    logger = logfilter.get_logger("test.once")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.warning("password=%s", "Hunter2", extra={"new_password": "Hunter3"})
    finally:
        logger.removeHandler(handler)
    assert len(calls) == 1
    assert stream.getvalue() == f"password={MASK} [{MASK}]\n"


# --- 6: one htmx detection -----------------------------------------------------------------


def test_htmx_detection_is_in_one_place():
    app_dir = Path(db.__file__).parent
    for path in app_dir.rglob("*.py"):
        source = path.read_text()
        if path.name != "templating.py":
            assert '"hx-request"' not in source, path
    request = SimpleNamespace(headers={"hx-request": "true"})
    assert is_hx(request)  # type: ignore[arg-type]
    assert not is_hx(SimpleNamespace(headers={}))  # type: ignore[arg-type]


# --- 7: profile delete refused, without htmx ---------------------------------------------


@pytest.mark.parametrize("htmx", [False, True])
def test_profile_delete_error_page_or_fragment(app, monkeypatch, htmx):  # noqa: F811
    exc = psycopg.errors.UndefinedObject('profile "p1" does not exist')
    monkeypatch.setattr(db, "drop_profile", _raise(exc))
    client, token = _client(app)
    headers = {"X-CSRF-Token": token}
    if htmx:
        headers["HX-Request"] = "true"
    response = client.post("/profiles/p1/delete", headers=headers)
    assert response.status_code == 422
    assert 'profile "p1" does not exist' in response.text.replace("&#34;", '"')
    if htmx:
        assert "<html" not in response.text and "HX-Retarget" not in response.headers
    else:
        assert "<h1>Error 422</h1>" in response.text and "<nav>" in response.text


# --- 8: one helper for the one-time password responses -----------------------------------


def test_reveal_response(app):  # noqa: F811
    @app.get("/_reveal")
    def reveal(request: Request, error: str | None = None):
        password = None if error else "Hunter2-pw"
        return reveal_response(
            request,
            "_reveal.html",
            {"reveal_role": "r1", "password": password},
            password=password,
            error=error,
        )

    client, _ = _client(app)
    shown = client.get("/_reveal")
    assert shown.status_code == 200
    assert shown.headers["Cache-Control"] == "no-store"
    assert shown.headers["Pragma"] == "no-cache"
    assert re.search(r'<code id="pw-[0-9a-f]{8}" class="secret">Hunter2-pw</code>', shown.text)
    refused = client.get("/_reveal", params={"error": "nope"})
    assert refused.status_code == 422
    assert "Pragma" not in refused.headers
    for module in (roles, pairs):
        source = inspect.getsource(module)
        assert "reveal_response(" in source
        assert "token_hex" not in source and "NO_STORE" not in source and "422" not in source
