"""Logging protection: no password may ever reach a log line.

install_log_masking() installs two hooks, once, for every logger and
handler (the ones uvicorn configures included):

- a LogRecord factory masks the arguments as soon as a record is created,
  and the formatted message when it may hold a secret (a secret-like word
  in the template or in a string argument, or an argument of another type
  than str / number / bool / None, whose text is unknown until formatted):
  the other records, most of them, are formatted once only, by their
  handler;
- Logger.makeRecord, wrapped on the Logger class itself (so that loggers
  created before the installation, the root logger and subclasses set with
  logging.setLoggerClass are covered), masks the `extra` attributes, which
  makeRecord sets on the record after the factory has returned.  They are
  thus masked before any filter, handler or formatter sees the record,
  whatever it reads (getMessage() or record.__dict__ directly).

Limits: a Logger subclass that overrides makeRecord without calling it
escapes the second hook (its `extra` attributes are not masked), and a
record rebuilt by logging.makeLogRecord(dict) escapes both: the factory is
called with an empty record, the dict's attributes (msg, args...) are set
afterwards.  No hook is installed on a logger or a handler for these cases:
a logger's filter does not see the records propagated from its children.
PasswordMaskFilter applies the same masking to a record on demand (as a
filter of one's own handler, for instance).  The application itself never
logs a password; this is a safety net.
"""

from __future__ import annotations

import logging
import re
from typing import Any

MASK = "***"

# cheap pre-check of the factory: a word that _VALUE_RE could match
_CANDIDATE_RE = re.compile(r"passw|passphrase|pwd|secret|token", re.IGNORECASE)
# argument types whose text is known without formatting them (str is searched)
_PLAIN_TYPES = (int, float, bool, type(None))

# keys / attribute names that denote a secret
_KEY_RE = re.compile(r"(pass(word|wd|phrase)?|pwd|secret|token|authorization)", re.IGNORECASE)
# "password=xxx", "password: xxx", "'password': 'xxx'", "PASSWORD 'xxx'", "passwd=xxx"...
_VALUE_RE = re.compile(
    r"""(?i)\b(password|passwd|passphrase|pwd|secret|token)\b"""
    r"""(["']?\s*(?:[=:]\s*|\s+(?=["'])))(["']?)([^\s"',;&]+)"""
)

_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
    "message",
    "asctime",
}


def mask_text(text: str) -> str:
    return _VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}", text)


def mask_value(value: Any) -> Any:
    """`value` with its secret-like content masked, never raising: MASK when
    masking it fails (a broken __eq__, a recursive container...)."""
    try:
        return _mask_value(value)
    except Exception:
        return MASK


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        return mask_text(value)
    # only the exact built-in containers are rebuilt: a subclass (namedtuple,
    # defaultdict, OrderedDict, a class of one's own) may not take its items
    # back through its constructor
    kind = type(value)
    if kind is dict:
        return _mask_dict(value)
    if kind is list:
        return [_mask_value(v) for v in value]
    if kind is tuple:
        return tuple(_mask_value(v) for v in value)
    if isinstance(value, dict | list | tuple):
        return _mask_subclass(value)
    return value


def _mask_dict(value: dict[Any, Any]) -> dict[Any, Any]:
    return {
        k: (MASK if isinstance(k, str) and _KEY_RE.search(k) else _mask_value(v))
        for k, v in value.items()
    }


def _mask_subclass(value: dict[Any, Any] | list[Any] | tuple[Any, ...]) -> Any:
    """A container subclass: kept as is (type and all) when nothing in it is
    secret-like, else replaced by the masked text of its content."""
    if isinstance(value, dict):
        plain: Any = dict(value)
        masked: Any = _mask_dict(plain)
    elif isinstance(value, tuple) and hasattr(value, "_fields"):  # namedtuple
        plain = dict(zip(value._fields, value, strict=False))
        masked = _mask_dict(plain)
    else:
        plain = list(value)
        masked = [_mask_value(v) for v in plain]
    if masked == plain:
        return value
    return f"{type(value).__name__}({masked!r})"


def _mask_extras(record: logging.LogRecord) -> None:
    """Masks the non-standard attributes (`extra`): the whole value for a
    secret-like name, the secret-like content of the others."""
    for key, value in list(record.__dict__.items()):
        if key in _STANDARD_ATTRS:
            continue
        if _KEY_RE.search(key):
            setattr(record, key, MASK)
        else:
            setattr(record, key, mask_value(value))


class PasswordMaskFilter(logging.Filter):
    """Masks any password-like content in a LogRecord (message, args, extras).

    The arguments are masked one by one (their types are kept: uvicorn's
    access formatter unpacks its five arguments), then the formatted message
    is checked: a secret only visible once the template and its arguments
    are joined ("password=%s" % ("Hunter2",), or "token:" in a path followed
    by the HTTP version) replaces the template by the masked message, its
    '%' escaped and followed by one "%.0s" per argument.  The arguments stay
    in place (same number, a formatter may unpack them) and each one
    formats to nothing: getMessage() gives the masked message.  The template
    itself is never masked alone: "password=%s" would become "password=***"
    with its argument left over, and the line would be lost to a formatting
    TypeError."""

    def filter(self, record: logging.LogRecord) -> bool:
        self.mask_message(record)
        _mask_extras(record)
        return True

    @staticmethod
    def mask_message(record: logging.LogRecord, *, check: bool = False) -> None:
        """Masks the template and the arguments (not the extras).  With
        `check`, the formatted message is built and masked only when it may
        hold a secret or fail (_needs_formatting())."""
        if not isinstance(record.msg, str):
            record.msg = mask_value(record.msg)
        if record.args:
            record.args = mask_value(record.args)
        if check and not _needs_formatting(record):
            return
        try:
            message = record.getMessage()
        except Exception:
            # A broken template (more placeholders than arguments...): the
            # masked template is kept and the arguments dropped.  Left in
            # place, they would be printed raw by logging.Handler.handleError
            # ("Arguments: ..."), and only a key or a "password=" pattern is
            # masked in them, not a bare password.
            record.msg = mask_value(record.msg)
            record.args = ()
        else:
            masked = mask_text(message)
            if masked != message:
                record.msg = _template_for(masked, record.args)


def _needs_formatting(record: logging.LogRecord) -> bool:
    """Whether mask_message() must build the formatted message of a record
    created by the factory: when it may hold a secret (a secret-like word in
    the template or in a str argument, or an argument whose text is unknown
    without formatting it: anything but str, numbers, bool and None), or
    when formatting it may fail (_formats_cleanly()): a broken template
    sends its raw arguments to logging.Handler.handleError, so they are
    dropped here.  A record with none of these words cannot form a secret
    once joined: it is left to its handler, which formats it once."""
    if not isinstance(record.msg, str) or _CANDIDATE_RE.search(record.msg):
        return True
    args = record.args
    if not args:
        return False
    if not isinstance(args, tuple | dict):
        return True
    values = args.values() if isinstance(args, dict) else args
    for arg in values:
        if isinstance(arg, str):
            if _CANDIDATE_RE.search(arg):
                return True
        elif not isinstance(arg, _PLAIN_TYPES):
            return True
    return not _formats_cleanly(record.msg, args)


# one %-conversion: (mapping key), flags, width, precision, length, type
_CONVERSION_RE = re.compile(
    r"%(?:\(([^)]*)\))?[#0\- +]*(\*|\d+)?(?:\.(\*|\d+))?[hlL]?([diouxXeEfFgGcrsa%])"
)
_NUMERIC_CONVERSIONS = frozenset("diouxXeEfFgG")


def _formats_cleanly(template: str, args: tuple[Any, ...] | dict[Any, Any]) -> bool:
    """Whether `template % args` surely succeeds, judged from the template
    alone and the types of the arguments (str, numbers, bool, None): every
    '%' starts a valid conversion, a numeric one gets a number, a tuple
    gives exactly one value per conversion, a mapping every key named.
    False when unsure ('*' width, %c, a mapping with positional
    conversions): the record is then formatted by the factory."""
    conversions = list(_CONVERSION_RE.finditer(template))
    if template.count("%") != sum(m.group(0).count("%") for m in conversions):
        return False
    wanted: list[Any] = []
    for m in conversions:
        key, width, precision, kind = m.groups()
        if kind == "%":
            continue
        if kind == "c" or width == "*" or precision == "*":
            return False
        if isinstance(args, dict):
            if key is None or key not in args:
                return False
            wanted.append((kind, args[key]))
        else:
            if key is not None:
                return False
            wanted.append((kind, None))
    if isinstance(args, tuple):
        if len(wanted) != len(args):
            return False
        wanted = [(kind, value) for (kind, _), value in zip(wanted, args, strict=True)]
    return all(
        kind not in _NUMERIC_CONVERSIONS or (isinstance(value, int | float))
        for kind, value in wanted
    )


def _template_for(message: str, args: Any) -> str:
    """A template giving `message` once formatted with `args`, whatever they are."""
    if not args:
        # getMessage() does not format a record without arguments
        return message
    template = message.replace("%", "%%")
    if isinstance(args, tuple):
        # "%.0s": any value, formatted with a zero precision (empty string)
        template += "%.0s" * len(args)
    # a mapping (logging's single-dict form) or no argument: nothing consumed
    return template


_FILTER = PasswordMaskFilter()
_installed = False


def install_log_masking() -> None:
    """Install the masking record factory and makeRecord wrapper, once."""
    global _installed
    if _installed:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        # no extra yet: makeRecord sets them after the factory (see below)
        _FILTER.mask_message(record, check=True)
        return record

    logging.setLogRecordFactory(factory)

    make_record = logging.Logger.makeRecord

    def masking_make_record(self: logging.Logger, *args: Any, **kwargs: Any) -> logging.LogRecord:
        record = make_record(self, *args, **kwargs)
        _mask_extras(record)
        return record

    logging.Logger.makeRecord = masking_make_record  # type: ignore[method-assign]
    _installed = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"pgpp_web.{name}")
