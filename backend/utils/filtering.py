"""Record filtering utilities for the mock API query layer.

Provides ``FilterSpec`` and ``apply_filters`` for applying URL query-parameter
filters to in-memory record lists.  Supports dot-path field access so nested
dicts (e.g. ``threatInfo.classification``) can be targeted directly.
"""
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi.exceptions import RequestValidationError
from pydantic import TypeAdapter, ValidationError

from utils.nested import get_nested as _get_field

#: Declared scalar types this module can check, and what checks them.
_DECLARED_TYPES: dict[str, Any] = {"integer": int, "boolean": bool}


def _reject_wrong_type(param: str, kind: str, raw: object) -> None:
    """Refuse a value the type the vendor declares cannot hold.

    The swagger types forty-odd of these parameters ``integer`` or
    ``boolean``; this mock took them all as text and compared whatever
    arrived. ``resolved=maybe`` was read as false and answered 200 with every
    unresolved threat, and ``coreCount__lt=abc`` answered 200 with the whole
    estate — in both cases a client with a formatting bug was handed a
    filtered-looking result and never told the filter had not been applied.

    ``limit=abc`` on this same mount has always answered 400 in
    SentinelOne's validation envelope; this is that rule reaching the filters
    the swagger types. Raising pydantic's own error rather than building the
    body here is deliberate: the envelope then comes from the one handler
    that was measured against the vendor, so the two cannot drift apart.
    """
    if not isinstance(raw, str):
        # A JSON body supplied a real integer or boolean; there is nothing to
        # parse and nothing to refuse.
        return
    try:
        TypeAdapter(_DECLARED_TYPES[kind]).validate_python(raw)
    except ValidationError as exc:
        raise RequestValidationError(
            [{**err, "loc": ("query", param)} for err in exc.errors()],
        ) from exc


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
        kind: The scalar type the swagger declares for the parameter, when it
              declares one this mock can check: ``"integer"``, ``"boolean"``,
              or ``"string"`` for everything it cannot. Array parameters are
              ``collectionFormat: csv`` throughout the swagger, so they arrive
              as text and stay ``"string"``.
    """

    param: str
    field: str
    type: str
    enum: bool = False
    kind: str = "string"


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
        if left_dt is not None and right_dt is None:
            # A timestamp on one side and a bare number on the other is the
            # epoch spelling, not two strings to sort alphabetically.
            right_dt = _epoch_ms(str(target))
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


def _epoch_ms(value: str) -> datetime | None:
    """Read a millisecond epoch, the spelling ``__between`` documents for dates.

    Every dated ``__between`` in the swagger is documented as
    ``<from_timestamp>-<to_timestamp>`` with a 13-digit example
    (``1514978764288-1514978999999``), while the records this mock holds carry
    ISO-8601. Comparing the two as text made *every* dated range answer with an
    empty list and a 200 — a range spanning the years 2000 to 2100 returned
    none of the sixty agents it must contain.
    """
    if not value.lstrip("-").isdigit():
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, UTC)
    except (OSError, OverflowError, ValueError):
        return None


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
        if spec.kind != "string":
            _reject_wrong_type(spec.param, spec.kind, raw)

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


def apply_query_options(
    records: list, params: dict, specs: list[FilterSpec] | None = None,
) -> list:
    """Apply the sorting and offset options every S1 list endpoint accepts.

    ``sortBy``, ``sortOrder`` and ``skip`` are documented on every list
    endpoint and were accepted and ignored, so a request asking for the second
    page by offset, or for a specific order, got the default list back and
    looked like it had worked.

    Args:
        records: Records already narrowed by :func:`apply_filters`.
        params:  Raw URL query parameters.
        specs:   The filter specs for this route, which already say where a
                 documented name lives on the record — the same knowledge a
                 documented `sortBy` needs.

    Returns:
        The records, sorted and offset as requested.
    """
    sort_by = str(params.get("sortBy") or "").strip()
    if sort_by:
        descending = str(params.get("sortOrder") or "asc").lower() == "desc"
        field = _sort_path(records, sort_by, specs or [])
        records = sorted(records, key=_sort_key(field), reverse=descending)

    skip = _as_int(params.get("skip"))
    if skip > 0:
        records = records[skip:]
    return records


def _sort_path(records: list, name: str, specs: list[FilterSpec]) -> str:
    """Where a documented sort field lives on these records.

    The vendor documents `sortBy=createdAt` for a threat whose record keeps
    that member inside `threatInfo`, so looking only at the top level found
    nothing, every key compared equal, and `sortOrder=asc` came back
    identical to `desc` — a client asking for an order got whatever order
    the store held, and was told nothing.

    Three ways to find it, in order of how much they are worth: the member
    itself, a documented filter that already names its path, and — for a
    name no filter mentions — the one nested object these records keep it
    in. An ambiguous name is left alone rather than guessed at.
    """
    first = records[0] if records else None
    if first is None or _get_field(first, name) is not None:
        return name
    for spec in specs:
        if spec.param.split("__")[0] == name:
            return spec.field
    for spec in specs:
        # A search spec names several fields at once (`a|b|c`); it says where
        # a term is looked for, not where one member lives.
        if "|" in spec.field:
            continue
        if spec.field == name or spec.field.endswith(f".{name}"):
            return spec.field
    holder = _nested_holder(records, name)
    return f"{holder}.{name}" if holder else name


def _nested_holder(records: list, name: str) -> str | None:
    """Which nested member carries *name*, when the records agree on one.

    A threat keeps `siteName` in both `agentRealtimeInfo` and
    `agentDetectionInfo`, so "the one nested object" needs deciding: a holder
    that is empty on every record is not one, and where the remaining
    holders carry the same value on every record the choice cannot change
    the order. Only a name whose holders genuinely disagree is left alone.
    """
    first = records[0]
    members = first if isinstance(first, dict) else getattr(first, "__dict__", {})
    holders: list[str] = [
        str(key) for key, value in members.items()
        if isinstance(value, dict) and name in value
    ]
    holders = [
        h for h in holders
        if any(_get_field(r, f"{h}.{name}") is not None for r in records)
    ]
    if not holders:
        return None
    reference = holders[0]
    for other in holders[1:]:
        if any(_get_field(r, f"{reference}.{name}") != _get_field(r, f"{other}.{name}")
               for r in records):
            return None
    return reference


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
