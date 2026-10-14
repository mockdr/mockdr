"""Cortex's ``filter_data`` request form, as ``get_alerts_by_filter_data`` takes it.

The XSOAR Cortex XDR integration (CoreIRApiModule ``get_alerts_by_filter_command``)
asks for alerts with ``request_data.filter_data``:

    {"filter": {"AND": [{"SEARCH_FIELD": "severity", "SEARCH_TYPE": "EQ",
                         "SEARCH_VALUE": "SEV_040_HIGH"},
                        {"OR": [...]}]},
     "sort": [{"FIELD": "source_insert_ts", "ORDER": "DESC"}],
     "paging": {"from": 0, "to": 50}}

-- a tree of ``AND``/``OR`` nodes over leaves naming an ``alert_fields``
member, a search type and a value, a sort on one member, and an absolute
``from``/``to`` slice. The search types are the module's own constants:
``EQ``, ``NEQ``, ``CONTAINS``, ``IP_MATCH``, ``IPLIST_MATCH``, ``IS_EMPTY``,
``NIS_EMPTY``, ``RANGE`` (``{"from", "to"}`` epoch milliseconds) and
``RELATIVE_TIMESTAMP`` (milliseconds back from now, as a string).
"""
from __future__ import annotations

import time
from typing import Any

from utils.xdr_filters import XdrFilterError

__all__ = ["apply_filter_data", "filter_data_page", "sort_filter_data"]


def _values(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _leaf(record: dict, node: dict) -> bool:  # noqa: PLR0911
    field = _text(node.get("SEARCH_FIELD"))
    kind = _text(node.get("SEARCH_TYPE")).upper()
    wanted = node.get("SEARCH_VALUE")
    held = record.get(field)
    if kind == "EQ":
        return any(_text(v) == _text(wanted) or v == wanted for v in _values(held))
    if kind == "NEQ":
        return not any(_text(v) == _text(wanted) or v == wanted for v in _values(held))
    if kind == "CONTAINS":
        needle = _text(wanted).lower()
        return any(needle in _text(v).lower() for v in _values(held))
    if kind in ("IP_MATCH", "IPLIST_MATCH"):
        return _text(wanted) in {_text(v).strip() for v in _values(held)}
    if kind == "IS_EMPTY":
        return _empty(held)
    if kind == "NIS_EMPTY":
        return not _empty(held)
    if kind == "RANGE":
        bounds = wanted if isinstance(wanted, dict) else {}
        number = _number(held)
        low, high = _number(bounds.get("from")), _number(bounds.get("to"))
        return number is not None and (low is None or number >= low) and (
            high is None or number <= high)
    if kind == "RELATIVE_TIMESTAMP":
        back, number = _number(wanted), _number(held)
        if back is None or number is None:
            return False
        return number >= time.time() * 1000 - back
    msg = f"Unsupported SEARCH_TYPE '{kind}'"
    raise XdrFilterError(msg)


def _matches(record: dict, node: Any) -> bool:
    if not isinstance(node, dict):
        msg = "A filter node must be an object"
        raise XdrFilterError(msg)
    if "AND" in node:
        return all(_matches(record, child) for child in _values(node["AND"]))
    if "OR" in node:
        children = _values(node["OR"])
        return not children or any(_matches(record, child) for child in children)
    return _leaf(record, node)


def apply_filter_data(records: list[dict], filter_data: dict) -> list[dict]:
    """The records ``filter_data.filter`` selects; all of them without one.

    Raises:
        XdrFilterError: On a node that is not an object or an unknown search type.
    """
    tree = filter_data.get("filter")
    if not tree:
        return list(records)
    return [r for r in records if _matches(r, tree)]


def sort_filter_data(records: list[dict], filter_data: dict) -> list[dict]:
    """Order by the first ``sort`` entry's ``FIELD`` and ``ORDER``."""
    sort = filter_data.get("sort")
    entry = sort[0] if isinstance(sort, list) and sort and isinstance(sort[0], dict) else None
    if entry is None or not entry.get("FIELD"):
        return list(records)
    field = str(entry["FIELD"])
    descending = _text(entry.get("ORDER")).upper() == "DESC"

    def key(record: dict) -> tuple[int, Any]:
        value = record.get(field)
        number = _number(value)
        return (0, number) if number is not None else (1, _text(value))

    present = [r for r in records if r.get(field) is not None]
    absent = [r for r in records if r.get(field) is None]
    return sorted(present, key=key, reverse=descending) + absent


def filter_data_page(records: list[dict], filter_data: dict) -> list[dict]:
    """The ``paging`` slice: ``from`` and ``to`` are absolute indices.

    Raises:
        XdrFilterError: When either is not a non-negative integer.
    """
    paging = filter_data.get("paging") or {}
    if not isinstance(paging, dict):
        msg = "paging must be an object"
        raise XdrFilterError(msg)
    start, end = paging.get("from", 0), paging.get("to", 100)
    for name, value in (("from", start), ("to", end)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            msg = f"paging.{name} must be a non-negative integer"
            raise XdrFilterError(msg)
    return records[start:end]
