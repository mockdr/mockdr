"""Reading a stored or requested value as a number."""
from __future__ import annotations

from typing import Any


def as_float(value: Any) -> float | None:  # noqa: ANN401 - any JSON or SPL value
    """*value* as a float, or None when it is not a number.

    A boolean is not a number here, though Python would make it one: a
    filter comparing ``true`` with ``1`` must not match. Five query engines
    (Elasticsearch aggregations, KQL, both Cortex filter dialects and SPL)
    each carried this function under its own name.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
