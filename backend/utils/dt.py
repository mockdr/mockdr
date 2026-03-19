"""UTC datetime utilities for the mock backend.

All timestamp generation in command handlers must use ``utc_now()`` from
this module — never call ``datetime.now()`` or ``datetime.utcnow()`` directly
(per TESTING.md §0 forbidden actions).
"""
from datetime import UTC, datetime


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string in S1 API format.

    Returns:
        Timestamp string formatted as ``YYYY-MM-DDTHH:MM:SS.000Z``.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
