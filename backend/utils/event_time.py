"""The time an indexed event carries: the record's own timestamp.

A SIEM add-on indexes an object at the object's creation time, so a bridge
event's ``_time`` must come from the record (``createdAt``,
``alertCreationTime``, ``creation_time`` …), not from a fixed epoch. Seed
records are dated relative to now; an event dated elsewhere is invisible to
every time-bounded search a client runs.
"""

from __future__ import annotations

import random
import time
from datetime import datetime

_MS_THRESHOLD = 1e11  # epochs above this are milliseconds


def parse_epoch(value: object) -> float | None:
    """``value`` as epoch seconds: ISO-8601, epoch seconds or milliseconds; None otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        return value / 1000.0 if value > _MS_THRESHOLD else float(value)
    if isinstance(value, str) and value:
        text = value.strip()
        try:
            number = float(text)
        except ValueError:
            pass
        else:
            return parse_epoch(number)
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _dig(payload: dict, path: str) -> object:
    node: object = payload
    for key in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def record_time(payload: dict, *paths: str, window: float = 86400 * 7) -> float:
    """The first parseable timestamp at ``paths``; else a random moment in the last ``window`` s."""
    for path in paths:
        epoch = parse_epoch(_dig(payload, path))
        if epoch is not None:
            return epoch
    return time.time() - random.uniform(0, window)  # noqa: S311 - seed data, not security
