"""Shared utility for traversing nested dicts via dot-separated key paths."""
from __future__ import annotations

from typing import Any


def get_nested(record: dict, path: str) -> Any:  # noqa: ANN401
    """Traverse a dict using a dot-separated key path.

    Args:
        record: The dict to traverse.
        path:   Dot-separated key path, e.g. ``"threatInfo.classification"``.

    Returns:
        The value at the path, or ``None`` if any segment is missing.
    """
    parts = path.split(".")
    val: Any = record
    for p in parts:
        if not isinstance(val, dict):
            return None
        val = val.get(p)
    return val
