"""In-memory ring buffer for recent webhook delivery attempts."""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class DeliveryEntry:
    """A single webhook delivery attempt record.

    Attributes:
        subscription_id: The webhook subscription that was targeted.
        event_type: The event type string, e.g. ``"threat.updated"``.
        status: ``"success"`` or ``"failure"``.
        attempt: Which attempt number this was (1-based).
        timestamp: ISO 8601 timestamp of the attempt.
        error: Error message if the delivery failed, empty string otherwise.
    """

    subscription_id: str
    event_type: str
    status: str  # "success" | "failure"
    attempt: int
    timestamp: str
    error: str = ""


_MAX_ENTRIES = 100
_lock = threading.Lock()
_entries: deque[DeliveryEntry] = deque(maxlen=_MAX_ENTRIES)


def record(entry: DeliveryEntry) -> None:
    """Append a delivery entry to the ring buffer (thread-safe)."""
    with _lock:
        _entries.append(entry)


def list_entries() -> list[dict[str, Any]]:
    """Return all entries as dicts, newest first."""
    with _lock:
        return [asdict(e) for e in reversed(_entries)]


def clear() -> int:
    """Clear all entries. Returns the number of entries that were removed."""
    with _lock:
        count = len(_entries)
        _entries.clear()
        return count
