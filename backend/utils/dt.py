"""UTC datetime utilities for the mock backend.

All timestamp generation in command handlers must use ``utc_now()`` from
this module — never call ``datetime.now()`` or ``datetime.utcnow()`` directly
(per TESTING.md §0 forbidden actions).
"""
from datetime import UTC, datetime, timedelta


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string in S1 API format.

    Returns:
        Timestamp string formatted as ``YYYY-MM-DDTHH:MM:SS.000Z``.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_utc(text: object) -> datetime | None:
    """An ISO-8601 instant as an aware datetime, or None if it is not one.

    ``Z`` and numeric offsets are both read; a moment without an offset is
    taken to be UTC, which is what every timestamp the mock writes means.
    """
    try:
        parsed = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso_ms(moment: datetime) -> str:
    """*moment* in ISO-8601 with milliseconds, UTC written ``Z``."""
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def plus_seconds(timestamp: str, seconds: float) -> str | None:
    """*timestamp* moved *seconds* later, in ISO-8601 with milliseconds; None if unreadable."""
    moment = parse_utc(timestamp)
    return None if moment is None else iso_ms(moment + timedelta(seconds=seconds))


def seconds_since(timestamp: str) -> float | None:
    """How long ago an ISO-8601 UTC timestamp was, or None if unreadable.

    Used to settle the states a real product settles asynchronously — a
    contained host, an isolated endpoint — so that a client which polls sees
    the state move rather than finding it already done or never done at all.
    """
    text = (timestamp or "").strip()
    parsed = parse_utc(text) if text else None
    if parsed is None:
        return None
    return (datetime.now(UTC) - parsed).total_seconds()
