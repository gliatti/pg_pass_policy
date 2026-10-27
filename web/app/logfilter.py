"""Logging protection: no password may ever reach a log line.

Two layers:
- a LogRecord factory that masks the arguments and the formatted message
  as soon as a record is created (covers every logger and handler, including the ones
  uvicorn configures);
- a logging.Filter attached to handlers, which also masks `extra` attributes.
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


class PasswordMaskFilter(logging.Filter):
    """Masks any password-like content in a LogRecord (message, args, extras).

    The arguments are masked one by one (their types are kept: uvicorn's
    access formatter unpacks them), then the formatted message is checked:
    a secret only visible once the template and its arguments are joined
    ("password=%s" % ("Hunter2",)) replaces the record's message by its
    masked form, arguments dropped.  The template itself is never masked
    alone: "password=%s" would become "password=***" with its argument left
    over, and the line would be lost to a formatting TypeError."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not isinstance(record.msg, str):
            record.msg = mask_value(record.msg)
        if record.args:
            record.args = mask_value(record.args)
        try:
            message = record.getMessage()
        except Exception:
            # a broken template: logging reports it (handleError), with
            # nothing left to leak
            record.msg = mask_value(record.msg)
        else:
            masked = mask_text(message)
            if masked != message:
                record.msg, record.args = masked, ()
        for key in list(record.__dict__):
            if key not in _STANDARD_ATTRS and _KEY_RE.search(key):
                setattr(record, key, MASK)
        return True


_FILTER = PasswordMaskFilter()
_installed = False


def install_log_masking() -> None:
    """Install the masking record factory (once) and the filter on known handlers."""
    global _installed
    if not _installed:
        previous = logging.getLogRecordFactory()

        def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = previous(*args, **kwargs)
            _FILTER.filter(record)
            return record

        logging.setLogRecordFactory(factory)
        _installed = True
    for name in (None, "uvicorn", "uvicorn.access", "uvicorn.error", "pgpp_web"):
        logger = logging.getLogger(name)
        if _FILTER not in logger.filters:
            logger.addFilter(_FILTER)
        for handler in logger.handlers:
            if _FILTER not in handler.filters:
                handler.addFilter(_FILTER)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"pgpp_web.{name}")
    if _FILTER not in logger.filters:
        logger.addFilter(_FILTER)
    return logger
