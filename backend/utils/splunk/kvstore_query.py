"""Query, projection, sort and paging for the KV Store data API.

``query``, ``fields``, ``sort``, ``limit`` and ``skip`` are all documented on
``GET storage/collections/data/{collection}``, and splunklib's
``KVStoreCollectionData.query()`` passes them. None were declared on the route,
so every one was dropped before the handler ran and the full collection came
back regardless of what was asked for.
"""
from __future__ import annotations

import functools
import json
import re
from collections.abc import Callable
from typing import Any

from utils.numbers import as_float
from utils.safe_regex import UnsafeRegexError, check_regex

__all__ = ["apply_fields", "apply_query", "apply_sort", "matches"]


def _ordered(lhs: float, rhs: float, op: str) -> bool:
    if op == "$gt":
        return lhs > rhs
    if op == "$gte":
        return lhs >= rhs
    if op == "$lt":
        return lhs < rhs
    return lhs <= rhs


def _ordered_text(lhs: str, rhs: str, op: str) -> bool:
    if op == "$gt":
        return lhs > rhs
    if op == "$gte":
        return lhs >= rhs
    if op == "$lt":
        return lhs < rhs
    return lhs <= rhs


def _compare(left: Any, right: Any, op: str) -> bool:
    """Compare numerically when both sides are numbers, else as text."""
    left_num, right_num = as_float(left), as_float(right)
    if left_num is None or right_num is None:
        return _ordered_text(str(left), str(right), op)
    return _ordered(left_num, right_num, op)


def _match_condition(value: Any, condition: Any) -> bool:
    """Match one field's value against a literal or an operator object."""
    if not isinstance(condition, dict):
        return str(value) == str(condition) or value == condition

    for op, operand in condition.items():
        if op in ("$gt", "$gte", "$lt", "$lte"):
            if not _compare(value, operand, op):
                return False
        elif op == "$ne":
            if str(value) == str(operand) or value == operand:
                return False
        elif op == "$in":
            if not any(str(value) == str(o) for o in operand):
                return False
        elif op == "$nin":
            if any(str(value) == str(o) for o in operand):
                return False
        elif op == "$exists":
            if bool(operand) != (value is not None):
                return False
        elif op == "$regex":
            pattern = _regex(str(operand))
            if pattern is None or not pattern.search(str(value)):
                return False
        else:
            # An operator we do not implement must not silently match.
            return False
    return True


@functools.lru_cache(maxsize=256)
def _regex(pattern: str) -> re.Pattern[str] | None:
    """*pattern* compiled, or None when it cannot be run safely.

    ``$regex`` went to ``re.search`` as it came: a pattern that does not
    compile raised out of the handler as a 500, and ``^(a+)+$`` against a
    thirty-character value held the worker for twenty-five seconds -- the
    ReDoS foothold :mod:`utils.safe_regex` closes for Splunk's other regex
    commands, Elasticsearch and KQL. Either selects nothing, as an
    unparseable query does here.
    """
    try:
        check_regex(pattern)
        return re.compile(pattern)
    except (re.error, UnsafeRegexError):
        return None


def matches(record: dict, query: dict) -> bool:
    """Whether *record* satisfies a KV Store query object."""
    for key, condition in query.items():
        if key == "$and":
            if not all(matches(record, sub) for sub in condition):
                return False
        elif key == "$or":
            if not any(matches(record, sub) for sub in condition):
                return False
        elif key == "$not":
            if matches(record, condition):
                return False
        elif not _match_condition(record.get(key), condition):
            return False
    return True


def apply_query(records: list[dict], query: str) -> list[dict]:
    """Filter *records* by a JSON query string.

    An unparseable query selects nothing rather than everything, so a typo
    cannot look like a successful unfiltered read.
    """
    if not query:
        return records
    try:
        parsed = json.loads(query)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, dict) or not parsed:
        return records
    return [r for r in records if matches(r, parsed)]


def apply_fields(records: list[dict], fields: str) -> list[dict]:
    """Apply a ``fields`` projection.

    Splunk takes a comma-separated list, optionally as ``name:1`` to include
    or ``name:0`` to exclude. ``_key`` is always returned.
    """
    if not fields:
        return records

    include: set[str] = set()
    exclude: set[str] = set()
    for token in fields.split(","):
        name, _, flag = token.strip().partition(":")
        name = name.strip()
        if not name:
            continue
        if flag.strip() == "0":
            exclude.add(name)
        else:
            include.add(name)

    projected: list[dict] = []
    for record in records:
        if include:
            kept = {k: v for k, v in record.items() if k in include or k == "_key"}
        else:
            kept = {k: v for k, v in record.items() if k not in exclude or k == "_key"}
        projected.append(kept)
    return projected


def apply_sort(records: list[dict], sort: str) -> list[dict]:
    """Sort by a comma-separated field list, ``-name`` for descending."""
    if not sort:
        return records

    ordered = list(records)
    for token in reversed([t.strip() for t in sort.split(",") if t.strip()]):
        descending = token.startswith("-")
        name = token.lstrip("+-").strip()
        if not name:
            continue
        ordered.sort(key=_sorter(name), reverse=descending)
    return ordered


def _sorter(field: str) -> Callable[[dict], tuple[int, float, str]]:
    """Build a sort key function bound to *field*."""
    def key(record: dict) -> tuple[int, float, str]:
        value = record.get(field)
        number = as_float(value)
        if number is not None:
            return (0, number, "")
        return (1, 0.0, str(value if value is not None else ""))
    return key
