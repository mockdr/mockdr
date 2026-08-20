"""Cortex XDR request-filter evaluation.

XDR request bodies carry ``filters: [{field, operator, value}]``. mockdr read
``field`` and ``value`` for three fields and ignored everything else —
including ``operator`` entirely — so a filter on ``category``, ``action`` or
``incident_id`` returned the full unfiltered set, and ``operator: "neq"`` was
applied as equality. Both are the kind of quiet wrongness a mock exists to
surface: XDR itself rejects an unsupported filter field rather than ignoring
it.
"""
from __future__ import annotations

from typing import Any

__all__ = ["XdrFilterError", "apply_xdr_filters"]


class XdrFilterError(ValueError):
    """Raised when a filter names an unsupported field or operator."""


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _numeric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(record_value: Any, operand: Any, operator: str) -> bool:  # noqa: PLR0911
    """Evaluate one XDR filter operator."""
    if operator in ("in", "in_list"):
        wanted = {_text(v).lower() for v in _as_list(operand)}
        # A list-valued field matches when any member matches.
        return any(_text(v).lower() in wanted for v in _as_list(record_value))
    if operator in ("nin", "not_in"):
        wanted = {_text(v).lower() for v in _as_list(operand)}
        return not any(_text(v).lower() in wanted for v in _as_list(record_value))
    if operator in ("eq", "="):
        return any(_text(v) == _text(operand) for v in _as_list(record_value))
    if operator in ("neq", "!="):
        return not any(_text(v) == _text(operand) for v in _as_list(record_value))
    if operator == "contains":
        needle = _text(operand).lower()
        return any(needle in _text(v).lower() for v in _as_list(record_value))
    if operator == "not_contains":
        needle = _text(operand).lower()
        return not any(needle in _text(v).lower() for v in _as_list(record_value))

    left, right = _numeric(record_value), _numeric(operand)
    if left is None or right is None:
        return False
    if operator == "gte":
        return left >= right
    if operator == "lte":
        return left <= right
    if operator == "gt":
        return left > right
    if operator == "lt":
        return left < right

    msg = f"Unsupported filter operator '{operator}'"
    raise XdrFilterError(msg)


def apply_xdr_filters(
    records: list[dict],
    filters: list[dict] | None,
    field_map: dict[str, str],
) -> list[dict]:
    """Apply an XDR ``filters`` block to *records*.

    Args:
        records:   Serialised records to narrow.
        filters:   The request's ``filters`` list.
        field_map: Filter field name -> record key, naming every field this
                   endpoint supports. A filter outside it is an error rather
                   than a silent pass-through.

    Returns:
        The records satisfying every filter.

    Raises:
        XdrFilterError: On an unsupported field or operator.
    """
    result = records
    for entry in filters or []:
        field = str(entry.get("field", ""))
        if field not in field_map:
            supported = ", ".join(sorted(field_map))
            msg = (
                f"Unsupported filter field '{field}'. "
                f"Supported fields: {supported}"
            )
            raise XdrFilterError(msg)

        key = field_map[field]
        operator = str(entry.get("operator") or "").lower()

        # `creation_time` style bounds arrive as gte/lte beside the field
        # rather than as an operator.
        if not operator:
            bounds = [(op, entry[op]) for op in ("gte", "lte") if entry.get(op) is not None]
            if bounds:
                for op, operand in bounds:
                    result = [r for r in result if _compare(r.get(key), operand, op)]
                continue
            operator = "in"

        operand = entry.get("value")
        result = [r for r in result if _compare(r.get(key), operand, operator)]
    return result
