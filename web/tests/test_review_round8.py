"""Unit tests, eighth review round: `extra` masked whatever the formatter
reads, broken templates without their raw arguments, internal errors of the
extension not shown as refusals, "extension not installed" page, versioned
CSS on the anonymous error page, worker_status() with partial rights,
ExtensionUnavailable as a plain value, no reread_failed flag."""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import io
import logging

import psycopg
import pytest

from app import db, logfilter
from app.logfilter import MASK, install_log_masking
from app.routers import roles
from app.templating import STATIC_DIR
from tests.test_review_round2 import _WorkerConn
from tests.test_review_round6 import (
    NotPreloaded,
    _client,
    _raise,
)
from tests.test_review_round6 import (
    app as app,  # noqa: F401 (fixture)
)


class _DictFormatter(logging.Formatter):
    """A formatter that never calls getMessage(): it dumps record.__dict__
    (a JSON formatter of the kind found in log shippers)."""

    def format(self, record: logging.LogRecord) -> str:
        return repr(sorted(record.__dict__.items(), key=lambda kv: kv[0]))


def _log_through(logger_name: str, formatter: logging.Formatter, emit) -> str:
    install_log_masking()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    level, propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    try:
        emit(logger)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
        logger.propagate = propagate
    return stream.getvalue()


# --- W1: extras masked before any formatter reads them --------------------------------


@pytest.mark.parametrize("name", ["pgpp_web.test.dict", "third.party.lib", None])
def test_extras_are_masked_for_a_formatter_reading_the_dict(name):
    out = _log_through(
        name or "",
        _DictFormatter(),
        lambda logger: logger.warning(
            "plain message",
            extra={"new_password": "Hunter-1", "detail": "conn password=Hunter-2", "n": 3},
        ),
    )
    assert "Hunter-1" not in out and "Hunter-2" not in out, out
    assert f"('new_password', '{MASK}')" in out
    assert f"password={MASK}" in out
    assert "('n', 3)" in out


def test_extras_masked_for_a_logger_created_before_the_installation():
    early = logging.getLogger("pgpp_web.test.created_early_" + str(id(object())))
    out = _log_through(
        early.name, _DictFormatter(), lambda logger: logger.info("x", extra={"token": "T0k3n"})
    )
    assert "T0k3n" not in out


def test_logger_adapter_extras_are_masked():
    out = _log_through(
        "pgpp_web.test.adapter",
        _DictFormatter(),
        lambda logger: logging.LoggerAdapter(logger, {"secret": "S3cr3t"}).info("x"),
    )
    assert "S3cr3t" not in out


def test_no_masked_record_class_left():
    assert not hasattr(logfilter, "MaskedLogRecord")
    record = logging.getLogger("pgpp_web.test.cls").makeRecord(
        "n", logging.INFO, __file__, 1, "m", (), None
    )
    assert type(record) is logging.LogRecord


# --- W2: broken template, its raw arguments are dropped --------------------------------


def test_broken_template_drops_its_arguments(capsys):
    out = _log_through(
        "pgpp_web.test.broken",
        logging.Formatter("%(message)s"),
        # two placeholders, one argument: getMessage() raises a TypeError
        lambda logger: logger.error("rotated %s with %s", "Bare-Hunter-3"),
    )
    err = capsys.readouterr().err
    assert "Bare-Hunter-3" not in out and "Bare-Hunter-3" not in err
    # nothing left to fail: no "--- Logging error ---" report
    assert "Logging error" not in err
    assert out == "rotated %s with %s\n"


def test_broken_template_record_has_no_args():
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "password=%s %s", ("Hunter-4",), None
    )
    logfilter.PasswordMaskFilter().filter(record)
    assert record.args == ()
    assert "Hunter-4" not in record.getMessage()


# --- W3: internal errors of the extension are not refusals ------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.InternalError_("pg_pass_policy: unexpected extension state 7"),
        psycopg.errors.UndefinedColumn('pg_pass_policy: column "x" is missing from the profile'),
        psycopg.errors.UndefinedFunction("PPP-001: something internal"),
    ],
)
def test_internal_errors_of_the_extension_propagate(exc, caplog):
    caplog.set_level(logging.WARNING)
    assert not db.is_extension_error(exc)
    assert "internal error of the extension" in caplog.text
    assert exc.sqlstate in caplog.text


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.InsufficientPrivilege("pg_pass_policy: permission denied"),
        psycopg.errors.UndefinedObject('pg_pass_policy: role "x" does not exist'),
        psycopg.errors.DuplicateObject('pg_pass_policy: profile "p" already exists'),
        psycopg.errors.InvalidParameterValue("pg_pass_policy: bad value"),
    ],
)
def test_refusals_of_the_extension_stay_inline(exc):
    assert db.is_extension_error(exc)


# --- W4: extension not installed -------------------------------------------------------


def _not_installed():
    return NotPreloaded("pg_pass_policy is not installed in this database", None)


def test_not_installed_detection():
    found = db.extension_unavailable(_not_installed())
    assert found == db.ExtensionUnavailable(
        "not_installed", "pg_pass_policy is not installed in this database", None
    )
    assert db.extension_unavailable(NotPreloaded()).reason == "not_preloaded"
    assert not db.is_extension_error(_not_installed())


def test_not_installed_is_a_dedicated_page(app, monkeypatch, caplog):  # noqa: F811
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(db, "status_counts", _raise(_not_installed()))
    client, _ = _client(app)
    response = client.get("/")
    assert response.status_code == 503
    assert "pg_pass_policy is not installed in this database</h1>" in response.text
    assert "CREATE EXTENSION pg_pass_policy" in response.text
    assert "<nav>" in response.text
    assert "pg_pass_policy is not installed (GET /)" in caplog.text


def test_not_installed_htmx_is_an_alert(app, monkeypatch):  # noqa: F811
    monkeypatch.setattr(db, "status_counts", _raise(_not_installed()))
    client, _ = _client(app)
    response = client.get("/", headers={"HX-Request": "true"})
    assert response.status_code == 503
    assert "pg_pass_policy is not installed in this database" in response.text
    assert response.headers["HX-Retarget"] == "#alerts"


def test_worker_status_not_installed_propagates():
    conn = _WorkerConn(_not_installed())
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        db.worker_status(conn)  # type: ignore[arg-type]
    assert conn.events == ["savepoint", "rollback"]


# --- W5: versioned CSS on the anonymous error page ----------------------------------------


def test_anonymous_error_page_versions_its_css(app):  # noqa: F811
    from fastapi.testclient import TestClient

    response = TestClient(app).get("/")  # no credentials: 401, anonymous page
    assert response.status_code == 401
    version = hashlib.sha256((STATIC_DIR / "app.css").read_bytes()).hexdigest()[:12]
    assert f'href="/static/app.css?v={version}"' in response.text
    assert "<nav>" not in response.text


# --- W6: worker_status() with partial rights --------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.InsufficientPrivilege("permission denied for function worker_status"),
        psycopg.errors.UndefinedFunction("function pass_policy.worker_status() does not exist"),
    ],
)
def test_worker_status_tolerates_partial_rights(exc, caplog):
    caplog.set_level(logging.WARNING)
    conn = _WorkerConn(exc)
    assert db.worker_status(conn) is None  # type: ignore[arg-type]
    assert conn.events == ["savepoint", "rollback"]
    assert f"worker status unavailable (SQLSTATE {exc.sqlstate})" in caplog.text


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.UndefinedTable("relation x does not exist"),
        psycopg.errors.SyntaxError("syntax error"),
    ],
)
def test_worker_status_other_programming_errors_propagate(exc):
    with pytest.raises(type(exc)):
        db.worker_status(_WorkerConn(exc))  # type: ignore[arg-type]


# --- W7: ExtensionUnavailable is a value, not an exception ------------------------------


def test_extension_unavailable_is_a_plain_value():
    assert dataclasses.is_dataclass(db.ExtensionUnavailable)
    assert not issubclass(db.ExtensionUnavailable, BaseException)
    assert not hasattr(db, "ExtensionNotPreloaded")
    assert "ExtensionNotPreloaded" not in inspect.getsource(db.run_action)


# --- W8: no reread_failed flag -----------------------------------------------------------


def test_row_template_relies_on_the_warning_only():
    assert "reread_failed" not in inspect.getsource(roles)
    template = (STATIC_DIR.parent / "templates" / "roles" / "_row.html").read_text()
    assert "reread_failed" not in template
    assert "{% elif warning %}" in template
