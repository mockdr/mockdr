"""Traverse a record by dot-separated path, whether it is a dict or an object.

A list endpoint filters and sorts over its whole collection to return one
page. Converting every stored record to a dict first — 2 400 conversions to
serve 100 rows, measured at forty times the default seed — is work thrown
away for all but the page. Reading the field straight off the dataclass
costs an attribute lookup, so the conversion can wait until the page is
known.
"""
from __future__ import annotations

from typing import Any


def get_nested(record: object, path: str) -> Any:  # noqa: ANN401
    """Traverse a dict or a dataclass using a dot-separated key path.

    Args:
        record: The dict or object to traverse.
        path:   Dot-separated key path, e.g. ``"threatInfo.classification"``.

    Returns:
        The value at the path, or ``None`` if any segment is missing. A
        dataclass whose field holds a dict is traversed through both.
    """
    val: Any = record
    for part in path.split("."):
        if val is None:
            return None
        if isinstance(val, dict):
            val = val.get(part)
        else:
            val = getattr(val, part, None)
    return val
