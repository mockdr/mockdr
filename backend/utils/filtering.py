"""Record filtering utilities for the mock API query layer.

Provides ``FilterSpec`` and ``apply_filters`` for applying URL query-parameter
filters to in-memory record lists.  Supports dot-path field access so nested
dicts (e.g. ``threatInfo.classification``) can be targeted directly.
"""
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from utils.nested import get_nested as _get_field


@dataclass
class FilterSpec:
    """Describes how a single URL query parameter maps to a record field filter.

    Attributes:
        param: URL query parameter name (e.g. ``"siteIds"``).
        field: Dot-path into the record dict (e.g. ``"agentDetectionInfo.siteId"``).
        type: Filter strategy — one of ``"eq"``, ``"in"``, ``"contains"``,
              ``"bool"``, ``"gte_dt"``, ``"lte_dt"``, ``"full_text"``.
    """

    param: str
    field: str
    type: str


def _parse_dt(value: str) -> datetime | None:
    """Parse an ISO-8601 datetime string into a ``datetime`` object.

    Tries multiple common S1 API timestamp formats in order.

    Args:
        value: Datetime string to parse.

    Returns:
        Parsed ``datetime``, or ``None`` if no format matched.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def apply_filters(records: list[dict], params: dict, specs: list[FilterSpec]) -> list[dict]:
    """Apply a sequence of filter specs to a list of records.

    Each spec is only applied when its corresponding ``params`` key is present
    and non-empty.  Specs are applied in order (AND semantics).

    Args:
        records: Full list of serialised domain records (dicts).
        params: Raw URL query parameters from the HTTP request.
        specs: Ordered list of ``FilterSpec`` definitions for this endpoint.

    Returns:
        Filtered subset of ``records`` that satisfy all active specs.
    """
    result = records
    for spec in specs:
        raw = params.get(spec.param)
        if raw is None or raw == "":
            continue

        if spec.type == "eq":
            result = [r for r in result if str(_get_field(r, spec.field) or "") == str(raw)]

        elif spec.type == "in":
            values = {v.strip() for v in str(raw).split(",")}
            result = [r for r in result if str(_get_field(r, spec.field) or "") in values]

        elif spec.type == "contains":
            needle = str(raw).lower()
            result = [r for r in result if needle in str(_get_field(r, spec.field) or "").lower()]

        elif spec.type == "bool":
            want = str(raw).lower() in ("true", "1", "yes")
            result = [r for r in result if bool(_get_field(r, spec.field)) == want]

        elif spec.type == "gte_dt":
            dt = _parse_dt(str(raw))
            if dt:
                result = [r for r in result if _compare_dt(_get_field(r, spec.field), dt, "gte")]

        elif spec.type == "lte_dt":
            dt = _parse_dt(str(raw))
            if dt:
                result = [r for r in result if _compare_dt(_get_field(r, spec.field), dt, "lte")]

        elif spec.type == "full_text":
            needle = str(raw).lower()
            fields = spec.field.split("|")
            result = [
                r for r in result
                if any(needle in str(_get_field(r, f) or "").lower() for f in fields)
            ]

    return result


def _compare_dt(field_val: Any, target: datetime, op: str) -> bool:
    """Compare a record's datetime field against a target using gte/lte.

    Args:
        field_val: Raw value from the record (will be parsed as ISO-8601).
        target: Parsed target ``datetime`` to compare against.
        op: ``"gte"`` or ``"lte"``.

    Returns:
        ``True`` if the comparison holds, ``False`` if the field is missing or unparseable.
    """
    if not field_val:
        return False
    parsed = _parse_dt(str(field_val))
    if not parsed:
        return False
    if op == "gte":
        return parsed >= target
    return parsed <= target
