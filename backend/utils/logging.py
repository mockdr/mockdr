"""Structured JSON logging configuration with request-id correlation."""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

# ContextVar holding the current request's ID (set by RequestLoggingMiddleware).
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class RequestIdFilter(logging.Filter):
    """Inject ``request_id`` from the contextvar onto every log record.

    This runs at record-creation time so the value is captured even if
    the contextvar is later reset (e.g. after the middleware finishes).
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        """Attach request_id and always return True (never suppress)."""
        record.request_id = request_id_var.get("")
        return True


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects.

    Fields emitted: timestamp (ISO 8601 UTC), level, logger, message,
    and request_id (captured by :class:`RequestIdFilter`).
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        """Return a JSON-encoded log line."""
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", request_id_var.get("")),
        }
        return json.dumps(payload, default=str)


def setup_logging(*, level: int = logging.INFO) -> None:
    """Configure the root logger with :class:`JSONFormatter` on *stderr*.

    Should be called once from ``main.py`` at import time.  Removes any
    pre-existing handlers on the root logger to avoid duplicate output.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to prevent duplicate lines in tests/reloads.
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)
