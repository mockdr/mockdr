"""Record filtering utilities for the mock API query layer.

Provides ``FilterSpec`` and ``apply_filters`` for applying URL query-parameter
filters to in-memory record lists.  Supports dot-path field access so nested
dicts (e.g. ``threatInfo.classification``) can be targeted directly.
"""
from collections.abc import Callable
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
        type: Filter strategy — one of ``"eq"``, ``"in"``, ``"nin"``,
              ``"contains"``, ``"bool"``, ``"gt"``, ``"gte"``, ``"lt"``,
              ``"lte"``, ``"between"``, ``"gte_dt"``, ``"lte_dt"``,
              ``"full_text"``. The four bare comparisons work on numbers and
              on ISO-8601 timestamps alike, which is how the vendor declares
              them: ``createdAt__gte`` and ``activeThreats__gt`` are the same
              operator over different fields.
        enum: The value comes from a declared set that the API spells one way
              in a filter and another in a response — SentinelOne accepts
              ``incidentStatus=UNRESOLVED`` and answers
              ``"incidentStatus": "Unresolved"``. Both forms then match.
    """

    param: str
    field: str
    type: str
    enum: bool = False


def _ordered(field_value: object, target: object, op: str) -> bool:
    """Compare a record's value with the filter's, as numbers or as timestamps.

    A field the record does not carry never satisfies a range: the vendor
    returns the rows it can compare, not the rows it cannot.
    """
    if field_value is None or target is None or target == "":
        return False
    left: object
    right: object
    try:
        left, right = float(str(field_value)), float(str(target))
    except (TypeError, ValueError):
        left_dt, right_dt = _parse_dt(str(field_value)), _parse_dt(str(target))
        if left_dt is None or right_dt is None:
            # Neither numbers nor timestamps: compare as text, which is what
            # an ordering over version strings and names amounts to.
            left, right = str(field_value), str(target)
        else:
            left, right = left_dt, right_dt
    if op == "gt":
        return left > right  # type: ignore[operator]
    if op == "gte":
        return left >= right  # type: ignore[operator]
    if op == "lt":
        return left < right  # type: ignore[operator]
    return left <= right  # type: ignore[operator]


def _enum_key(value: object) -> str:
    """A declared value in a form both spellings share (``TRUE_POSITIVE``/``True positive``)."""
    return str(value).strip().lower().replace("_", " ")


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


def apply_filters(records: list, params: dict, specs: list[FilterSpec]) -> list:
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

        elif spec.type == "in":  # noqa: SIM114 - the enum branch differs below
            # Query params arrive comma-separated, request bodies as JSON
            # arrays. Splitting unconditionally turned ["abc"] into the literal
            # "['abc']", so a body-supplied filter silently matched nothing.
            if isinstance(raw, (list, tuple, set)):
                values = {str(v).strip() for v in raw}
            else:
                values = {v.strip() for v in str(raw).split(",")}
            if spec.enum:
                wanted = {_enum_key(v) for v in values}
                result = [
                    r for r in result if _enum_key(_get_field(r, spec.field) or "") in wanted
                ]
            else:
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

        elif spec.type == "nin":
            if isinstance(raw, (list, tuple, set)):
                values = {str(v).strip() for v in raw}
            else:
                values = {v.strip() for v in str(raw).split(",")}
            if spec.enum:
                unwanted = {_enum_key(v) for v in values}
                result = [
                    r for r in result
                    if _enum_key(_get_field(r, spec.field) or "") not in unwanted
                ]
            else:
                result = [r for r in result if str(_get_field(r, spec.field) or "") not in values]

        elif spec.type in ("gt", "gte", "lt", "lte"):
            result = [r for r in result if _ordered(_get_field(r, spec.field), raw, spec.type)]

        elif spec.type == "between":
            # The vendor spells a range as "low-high" in one parameter.
            low, _, high = str(raw).partition("-")
            result = [
                r for r in result
                if _ordered(_get_field(r, spec.field), low.strip(), "gte")
                and _ordered(_get_field(r, spec.field), high.strip(), "lte")
            ]

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


def apply_query_options(records: list, params: dict) -> list:
    """Apply the sorting and offset options every S1 list endpoint accepts.

    ``sortBy``, ``sortOrder`` and ``skip`` are documented on every list
    endpoint and were accepted and ignored, so a request asking for the second
    page by offset, or for a specific order, got the default list back and
    looked like it had worked.

    Args:
        records: Records already narrowed by :func:`apply_filters`.
        params:  Raw URL query parameters.

    Returns:
        The records, sorted and offset as requested.
    """
    sort_by = str(params.get("sortBy") or "").strip()
    if sort_by:
        descending = str(params.get("sortOrder") or "asc").lower() == "desc"
        records = sorted(records, key=_sort_key(sort_by), reverse=descending)

    skip = _as_int(params.get("skip"))
    if skip > 0:
        records = records[skip:]
    return records


def _as_int(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _sort_key(field: str) -> Callable[[Any], tuple[int, float, str]]:
    """Build a sort key that orders numbers numerically and Nones last."""
    def key(record: Any) -> tuple[int, float, str]:  # noqa: ANN401 - dict or record
        value = _get_field(record, field)
        if value is None:
            return (2, 0.0, "")
        try:
            return (0, float(value), "")
        except (TypeError, ValueError):
            return (1, 0.0, str(value))
    return key
