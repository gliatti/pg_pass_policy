"""Logging protection: no password may ever reach a log line.

install_log_masking() installs two hooks, once, for every logger and
handler (the ones uvicorn configures included):

- a LogRecord factory masks the arguments and the formatted message as soon
  as a record is created, once per record;
- Logger.makeRecord, wrapped on the Logger class itself (so that loggers
  created before the installation, the root logger and subclasses set with
  logging.setLoggerClass are covered), masks the `extra` attributes, which
  makeRecord sets on the record after the factory has returned.  They are
  thus masked before any filter, handler or formatter sees the record,
  whatever it reads (getMessage() or record.__dict__ directly).

A Logger subclass that overrides makeRecord without calling it, or a record
built by hand (logging.makeLogRecord), escapes the second hook:
PasswordMaskFilter, put on a handler, covers that case.
The application itself never logs a password; this is a safety net.
"""

from __future__ import annotations

import logging
import re
from typing import Any

MASK = "***"

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
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {
            k: (MASK if isinstance(k, str) and _KEY_RE.search(k) else mask_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        masked = [mask_value(v) for v in value]
        if hasattr(value, "_fields"):  # namedtuple
            return type(value)(*masked)
        return type(value)(masked)
    return value


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
    def mask_message(record: logging.LogRecord) -> None:
        """Masks the template and the arguments (not the extras)."""
        if not isinstance(record.msg, str):
            record.msg = mask_value(record.msg)
        if record.args:
            record.args = mask_value(record.args)
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
        _FILTER.mask_message(record)
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
