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


def seconds_since(timestamp: str) -> float | None:
    """How long ago an ISO-8601 UTC timestamp was, or None if unreadable.

    Used to settle the states a real product settles asynchronously — a
    contained host, an isolated endpoint — so that a client which polls sees
    the state move rather than finding it already done or never done at all.
    """
    text = (timestamp or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).total_seconds()
