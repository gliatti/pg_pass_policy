"""Unit tests, ninth review round: "not installed" detected from the real
errors (3F000, 42P01 checked against pg_extension), container subclasses
masked without raising, any 55000 kept off the refusals, a pair switch
without a row as a 200 warning, records formatted by the factory only when
needed, one log line per database error, one table per unavailable state."""

from __future__ import annotations

import collections
import io
import logging
import typing
from contextlib import contextmanager
from types import SimpleNamespace

import psycopg
import pytest

from app import db, logfilter, main
from app.logfilter import MASK, install_log_masking, mask_value
from tests.test_review_round6 import FakeConn, FakePool, _client, _raise
from tests.test_review_round6 import app as app  # noqa: F401 (fixture)

MISSING_SCHEMA = 'schema "pass_policy" does not exist'
MISSING_VIEW = 'relation "pass_policy.v_role_status" does not exist'


# --- 1: extension not installed, from the errors the server really raises -----------------


def test_missing_schema_is_not_installed():
    found = db.extension_unavailable(psycopg.errors.InvalidSchemaName(MISSING_SCHEMA))
    assert found is not None and found.reason == "not_installed"
    assert found.message == MISSING_SCHEMA
    other = psycopg.errors.InvalidSchemaName('schema "elsewhere" does not exist')
    assert db.extension_unavailable(other) is None
    # a missing relation alone is not enough (get_conn() checks pg_extension)
    assert db.extension_unavailable(psycopg.errors.UndefinedTable(MISSING_VIEW)) is None


class _ExtConn(FakeConn):
    """A connection answering the pg_extension check with `installed`."""

    def __init__(self, events, installed):
        super().__init__(events)
        self.installed = installed
        self.queries = []

    def execute(self, query, *args, **kwargs):
        self.queries.append(query)
        return SimpleNamespace(fetchone=lambda: {"n": int(self.installed)}, fetchall=list)


@pytest.mark.parametrize("installed", [False, True])
def test_missing_extension_error(installed):
    conn = _ExtConn([], installed)
    found = db.missing_extension_error(conn, psycopg.errors.UndefinedTable(MISSING_VIEW))
    assert conn.events == ["check rollback"]
    assert "pg_extension" in conn.queries[0]
    if installed:
        # an installed extension out of step with the back-office: a plain error
        assert found is None
    else:
        assert isinstance(found, psycopg.errors.ObjectNotInPrerequisiteState)
        assert db.extension_unavailable(found).reason == "not_installed"


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.UndefinedTable('relation "public.other" does not exist'),
        psycopg.errors.UndefinedTable("relation x does not exist"),
        psycopg.errors.SyntaxError("pass_policy.v_role_status"),
    ],
)
def test_missing_extension_error_ignores_other_errors(exc):
    conn = _ExtConn([], False)
    assert db.missing_extension_error(conn, exc) is None
    assert conn.queries == [] and conn.events == []


class _ExtPool(FakePool):
    def __init__(self, events, installed):
        super().__init__(events)
        self.installed = installed

    @contextmanager
    def connection(self):
        try:
            yield _ExtConn(self.events, self.installed)
        except BaseException:
            self.events.append("request rollback")
            raise


@pytest.mark.parametrize("installed", [False, True])
def test_missing_view_page(app, monkeypatch, caplog, installed):  # noqa: F811
    caplog.set_level(logging.ERROR)
    app.state.pool = _ExtPool([], installed)
    monkeypatch.setattr(db, "status_counts", _raise(psycopg.errors.UndefinedTable(MISSING_VIEW)))
    client, _ = _client(app)
    response = client.get("/")
    if installed:
        assert response.status_code == 500
        assert "Database error, see the server log" in response.text
        assert "database error on GET / [SQLSTATE 42P01]" in caplog.text
    else:
        assert response.status_code == 503
        assert "pg_pass_policy is not installed in this database</h1>" in response.text
        assert "pg_pass_policy is not installed (GET /) [SQLSTATE 55000]" in caplog.text
        assert f"(from: {MISSING_VIEW})" in caplog.text
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1


def test_missing_schema_page(app, monkeypatch):  # noqa: F811
    exc = psycopg.errors.InvalidSchemaName(MISSING_SCHEMA)
    monkeypatch.setattr(db, "status_counts", _raise(exc))
    client, _ = _client(app)
    response = client.get("/")
    assert response.status_code == 503
    assert "pg_pass_policy is not installed in this database</h1>" in response.text
    assert MISSING_SCHEMA.replace('"', "&#34;") in response.text


# --- 2: container subclasses ---------------------------------------------------------------

Creds = collections.namedtuple("Creds", "user password")
Point = collections.namedtuple("Point", "x y")


def test_namedtuple_kept_or_masked():
    point = Point(1, "a")
    assert mask_value(point) is point
    masked = mask_value(Creds("bob", "Hunter2"))
    assert isinstance(masked, str) and "Hunter2" not in masked
    assert masked == f"Creds({{'user': 'bob', 'password': '{MASK}'}})"


def test_defaultdict_and_ordereddict():
    plain = collections.defaultdict(list, {"a": [1]})
    assert mask_value(plain) is plain
    secret = collections.defaultdict(list, {"password": "Hunter2", "a": "x"})
    masked = mask_value(secret)
    assert "Hunter2" not in masked and masked.startswith("defaultdict(")
    ordered = collections.OrderedDict(token="Tok-1", user="bob")
    masked = mask_value(ordered)
    assert "Tok-1" not in masked and "bob" in masked
    # nested in an exact container: rebuilt around it
    assert (
        mask_value({"k": [ordered]})["k"][0] == f"OrderedDict({{'token': '{MASK}', 'user': 'bob'}})"
    )


def test_exact_containers_rebuilt():
    assert mask_value({"password": "x", "n": ("a", ["password=y"])}) == {
        "password": MASK,
        "n": ("a", [f"password={MASK}"]),
    }


class _BrokenTuple(tuple):
    @property
    def _fields(self):
        raise RuntimeError("broken")


def test_mask_value_never_raises():
    assert mask_value(_BrokenTuple(("password=x",))) == MASK
    loop: list = []
    loop.append(loop)
    assert mask_value(loop) == MASK


def _emit(emit) -> str:
    install_log_masking()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("pgpp_web.test.round9")
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    try:
        emit(logger)
    finally:
        logger.removeHandler(handler)
    return stream.getvalue()


def test_subclasses_logged_without_error(capsys):
    out = _emit(
        lambda log: (
            log.info("creds %s", Creds("bob", "Hunter2")),
            log.info("point %s", Point(1, 2)),
            log.info("map %(a)s", collections.defaultdict(int, {"a": 1})),
            log.info("od %s", collections.OrderedDict(secret="S3cr3t")),
            log.info("creds", extra={"creds": Creds("bob", "Hunter2")}),
        )
    )
    err = capsys.readouterr().err
    assert "Logging error" not in err
    assert "Hunter2" not in out and "S3cr3t" not in out
    assert "point Point(x=1, y=2)" in out
    assert "map 1" in out


# --- 3: any 55000 off the refusals ---------------------------------------------------------


def test_untrusted_schema_is_not_a_refusal(app, monkeypatch, caplog):  # noqa: F811
    exc = psycopg.errors.ObjectNotInPrerequisiteState(
        "PPP-004: pg_pass_policy schema is not trusted"
    )
    assert not db.is_extension_error(exc)
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(db, "lock_role", _raise(exc))
    client, token = _client(app)
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    response = client.post("/roles/r1/lock", headers=headers)
    assert response.status_code == 500
    assert "PPP-004" not in response.text
    assert "database error on POST /roles/r1/lock [SQLSTATE 55000]: PPP-004" in caplog.text


# --- 4: pair switch without a row -----------------------------------------------------------


def test_switch_without_a_row_reads_the_list_normally(app, monkeypatch):  # noqa: F811
    reads = []
    monkeypatch.setattr(db, "switch_pair", lambda conn, pair, length: None)
    monkeypatch.setattr(db, "reread_after_commit", _raise(AssertionError("not this path")))

    def list_pairs(conn):
        reads.append(conn)
        return [{"pair_name": "p1", "role_a": "a", "role_b": "b", "group_role": "g"}]

    monkeypatch.setattr(db, "list_pairs", list_pairs)
    client, token = _client(app)
    response = client.post(
        "/pairs/p1/switch", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    assert response.status_code == 200, response.text
    assert len(reads) == 1
    assert 'class="alert alert-warn"' in response.text
    assert "Pair list unavailable." not in response.text
    assert "<strong>p1</strong>" in response.text


# --- 5: the factory formats a record only when needed ----------------------------------------


@pytest.mark.parametrize(
    ("msg", "args", "expected", "formats"),
    [
        # no secret-like word, plain arguments, a clean template: left to the handler
        ("role %s locked for %d s", ("bob", 3), "role bob locked for 3 s", 0),
        ("%(a)s=%(b).1f", ({"a": "x", "b": 2},), "x=2.0", 0),
        ("100%% done of %s", ("x",), "100% done of x", 0),
        ("no argument", (), "no argument", 0),
        # a secret-like word in the template or a str argument: formatted
        ("password=%s", ("Hunter2",), f"password={MASK}", 1),
        ("GET %s", ("/x?token=abc",), f"GET /x?token={MASK}", 1),
        # an argument of another type: its text is unknown, formatted
        ("err: %s", (ValueError("pwd=x"),), f"err: pwd={MASK}", 1),
    ],
)
def test_factory_formats_only_when_needed(monkeypatch, msg, args, expected, formats):
    install_log_masking()
    calls = []
    real = logging.LogRecord.getMessage

    def spy(self):
        calls.append(self.msg)
        return real(self)

    monkeypatch.setattr(logging.LogRecord, "getMessage", spy)
    factory = logging.getLogRecordFactory()
    record = factory("pgpp_web.t", logging.INFO, __file__, 1, msg, args, None)
    assert len(calls) == formats
    monkeypatch.undo()
    assert record.getMessage() == expected


@pytest.mark.parametrize(
    ("template", "args"),
    [
        ("rotated %s with %s", ("Bare-1",)),  # too few arguments
        ("rotated %s", ("Bare-1", "x")),  # too many
        ("count %d", ("Bare-1",)),  # numeric conversion of a str
        ("value %(a)s", {"b": "Bare-1"}),  # missing key
        ("width %*d", (3, 4)),  # unsure: formatted
        ("bad %y", ("Bare-1",)),  # invalid conversion
    ],
)
def test_unclean_templates_are_formatted(template, args):
    assert not logfilter._formats_cleanly(template, args)


def test_broken_template_without_secret_word_drops_args(capsys):
    out = _emit(lambda log: log.error("count %d", "Bare-2"))
    err = capsys.readouterr().err
    assert "Bare-2" not in out and "Bare-2" not in err
    assert "Logging error" not in err


# --- 7: one log line per database error -----------------------------------------------------


def test_internal_error_logged_once_with_sqlstate(app, monkeypatch, caplog):  # noqa: F811
    caplog.set_level(logging.DEBUG)
    exc = psycopg.errors.InternalError_("pg_pass_policy: unexpected extension state 7")
    monkeypatch.setattr(db, "lock_role", _raise(exc))
    client, token = _client(app)
    caplog.clear()
    response = client.post("/roles/r1/lock", headers={"X-CSRF-Token": token})
    assert response.status_code == 500
    lines = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(lines) == 1 and lines[0].levelno == logging.ERROR
    assert "[SQLSTATE XX000]" in lines[0].getMessage()


# --- 8: one table per unavailable state -----------------------------------------------------


def test_one_table_per_reason():
    reasons = typing.get_args(typing.get_type_hints(db.ExtensionUnavailable)["reason"])
    assert set(main.UNAVAILABLE_PAGES) == set(reasons)
    for label, template in main.UNAVAILABLE_PAGES.values():
        assert template == f"not_{label}.html"
