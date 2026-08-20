"""Elasticsearch aggregation support.

``aggs`` was read past entirely: a body asking for a terms breakdown got back
a normal hit list and **no** ``aggregations`` key at all. A client that builds
a dashboard or a summary off aggregations therefore saw an empty chart rather
than an error, which is the failure mode a mock is supposed to expose.

Implements the aggregations a SIEM client actually sends: ``terms``,
``date_histogram``, ``histogram``, ``range``, ``filter``, ``filters``,
``cardinality``, ``value_count``, ``min``, ``max``, ``sum``, ``avg``,
``stats``, and ``top_hits`` — with sub-aggregations nested underneath.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any

from utils.es_query import _build_predicate, wrap_as_hits
from utils.nested import get_nested

__all__ = ["ESAggregationError", "apply_aggregations"]

_MAX_DEPTH = 10

# Bucket aggregations get sub-aggregations; metric aggregations do not.
_BUCKET_TYPES = frozenset({
    "terms", "date_histogram", "histogram", "range", "filter", "filters",
})
_METRIC_TYPES = frozenset({
    "avg", "cardinality", "max", "min", "stats", "sum", "top_hits",
    "value_count",
})


class ESAggregationError(ValueError):
    """Raised when an aggregation cannot be understood.

    Elasticsearch answers an unknown aggregation type with a 400; returning a
    silently empty result would be worse than the original bug.
    """


def apply_aggregations(
    records: list[dict],
    aggs: dict,
    *,
    index: str = "",
    _depth: int = 0,
) -> dict:
    """Evaluate an ``aggs`` block against *records*.

    Args:
        records: The documents the query selected.
        aggs:    The ``aggs`` (or ``aggregations``) block.
        index:   Index name, used when ``top_hits`` wraps documents.
        _depth:  Recursion guard for nested sub-aggregations.

    Returns:
        The ``aggregations`` response object.

    Raises:
        ESAggregationError: On an unknown or malformed aggregation.
    """
    if _depth > _MAX_DEPTH:
        msg = "aggregations nested too deeply"
        raise ESAggregationError(msg)

    result: dict[str, Any] = {}
    for name, definition in aggs.items():
        if not isinstance(definition, dict):
            msg = f"[{name}] is not a valid aggregation definition"
            raise ESAggregationError(msg)
        result[name] = _evaluate(name, definition, records, index, _depth)
    return result


def _split_definition(name: str, definition: dict) -> tuple[str, dict, dict]:
    """Separate the aggregation type from its nested sub-aggregations."""
    sub = definition.get("aggs") or definition.get("aggregations") or {}
    types = [k for k in definition if k not in ("aggs", "aggregations", "meta")]
    if len(types) != 1:
        msg = f"[{name}] must declare exactly one aggregation type"
        raise ESAggregationError(msg)
    agg_type = types[0]
    body = definition[agg_type]
    return agg_type, body if isinstance(body, dict) else {}, sub


def _evaluate(
    name: str, definition: dict, records: list[dict], index: str, depth: int,
) -> dict:
    agg_type, body, sub = _split_definition(name, definition)

    if agg_type in _BUCKET_TYPES:
        return _bucket(agg_type, body, sub, records, index, depth)
    if agg_type in _METRIC_TYPES:
        return _metric(agg_type, body, records, index)

    msg = f"Unknown aggregation type [{agg_type}]"
    raise ESAggregationError(msg)


# ---------------------------------------------------------------------------
# Bucket aggregations
# ---------------------------------------------------------------------------

def _bucket(
    agg_type: str,
    body: dict,
    sub: dict,
    records: list[dict],
    index: str,
    depth: int,
) -> dict:
    if agg_type == "terms":
        return _terms(body, sub, records, index, depth)
    if agg_type == "date_histogram":
        return _date_histogram(body, sub, records, index, depth)
    if agg_type == "histogram":
        return _histogram(body, sub, records, index, depth)
    if agg_type == "range":
        return _range(body, sub, records, index, depth)
    if agg_type == "filter":
        matched = [r for r in records if _build_predicate(body)(r)]
        return _with_sub({"doc_count": len(matched)}, sub, matched, index, depth)
    # filters
    return _filters(body, sub, records, index, depth)


def _terms(body: dict, sub: dict, records: list[dict], index: str, depth: int) -> dict:
    field = body.get("field", "")
    size = int(body.get("size", 10))
    min_doc_count = int(body.get("min_doc_count", 1))

    groups: OrderedDict[Any, list[dict]] = OrderedDict()
    for record in records:
        value = get_nested(record, field)
        if value is None:
            continue
        # A keyword array produces one bucket per member, as in real ES.
        keys = value if isinstance(value, list) else [value]
        for key in keys:
            groups.setdefault(key, []).append(record)

    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))
    kept = [(k, v) for k, v in ordered if len(v) >= min_doc_count]
    buckets = [
        _with_sub({"key": key, "doc_count": len(members)}, sub, members, index, depth)
        for key, members in kept[:size]
    ]
    return {
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": sum(len(v) for _, v in kept[size:]),
        "buckets": buckets,
    }


def _date_histogram(
    body: dict, sub: dict, records: list[dict], index: str, depth: int,
) -> dict:
    field = body.get("field", "")
    interval = _interval_seconds(
        body.get("fixed_interval") or body.get("calendar_interval")
        or body.get("interval") or "1d",
    )

    groups: OrderedDict[float, list[dict]] = OrderedDict()
    for record in records:
        stamp = _as_epoch(get_nested(record, field))
        if stamp is None:
            continue
        groups.setdefault((stamp // interval) * interval, []).append(record)

    buckets = []
    for start in sorted(groups):
        members = groups[start]
        bucket = {
            "key": int(start * 1000),
            "key_as_string": datetime.fromtimestamp(start, tz=UTC).isoformat(),
            "doc_count": len(members),
        }
        buckets.append(_with_sub(bucket, sub, members, index, depth))
    return {"buckets": buckets}


def _histogram(
    body: dict, sub: dict, records: list[dict], index: str, depth: int,
) -> dict:
    field = body.get("field", "")
    interval = float(body.get("interval", 1) or 1)

    groups: OrderedDict[float, list[dict]] = OrderedDict()
    for record in records:
        value = _as_float(get_nested(record, field))
        if value is None:
            continue
        groups.setdefault((value // interval) * interval, []).append(record)

    buckets = [
        _with_sub(
            {"key": _shrink(start), "doc_count": len(groups[start])},
            sub, groups[start], index, depth,
        )
        for start in sorted(groups)
    ]
    return {"buckets": buckets}


def _range(body: dict, sub: dict, records: list[dict], index: str, depth: int) -> dict:
    field = body.get("field", "")
    buckets = []
    for spec in body.get("ranges", []):
        lower = _as_float(spec.get("from"))
        upper = _as_float(spec.get("to"))
        members = [
            r for r in records
            if _in_range(_as_float(get_nested(r, field)), lower, upper)
        ]
        bucket: dict[str, Any] = {
            "key": spec.get("key") or _range_key(lower, upper),
            "doc_count": len(members),
        }
        if lower is not None:
            bucket["from"] = lower
        if upper is not None:
            bucket["to"] = upper
        buckets.append(_with_sub(bucket, sub, members, index, depth))
    return {"buckets": buckets}


def _filters(body: dict, sub: dict, records: list[dict], index: str, depth: int) -> dict:
    named = body.get("filters", {})
    if isinstance(named, dict):
        buckets: dict[str, Any] = {}
        for key, clause in named.items():
            members = [r for r in records if _build_predicate(clause)(r)]
            buckets[key] = _with_sub(
                {"doc_count": len(members)}, sub, members, index, depth,
            )
        return {"buckets": buckets}

    anonymous = []
    for clause in named:
        members = [r for r in records if _build_predicate(clause)(r)]
        anonymous.append(
            _with_sub({"doc_count": len(members)}, sub, members, index, depth),
        )
    return {"buckets": anonymous}


def _with_sub(
    bucket: dict, sub: dict, members: list[dict], index: str, depth: int,
) -> dict:
    """Attach sub-aggregation results to a bucket."""
    if not sub:
        return bucket
    return {**bucket, **apply_aggregations(members, sub, index=index, _depth=depth + 1)}


# ---------------------------------------------------------------------------
# Metric aggregations
# ---------------------------------------------------------------------------

def _metric(agg_type: str, body: dict, records: list[dict], index: str) -> dict:
    field = body.get("field", "")

    if agg_type == "value_count":
        return {"value": sum(1 for r in records if get_nested(r, field) is not None)}
    if agg_type == "cardinality":
        seen = {
            str(get_nested(r, field))
            for r in records
            if get_nested(r, field) is not None
        }
        return {"value": len(seen)}
    if agg_type == "top_hits":
        size = int(body.get("size", 3))
        hits = wrap_as_hits(records[:size], index=index or ".siem-signals-default")
        return {
            "hits": {
                "total": {"value": len(records), "relation": "eq"},
                "max_score": 1.0 if hits else None,
                "hits": hits,
            },
        }

    numbers = [
        n for n in (_as_float(get_nested(r, field)) for r in records) if n is not None
    ]
    if agg_type == "stats":
        return {
            "count": len(numbers),
            "min": _shrink(min(numbers)) if numbers else None,
            "max": _shrink(max(numbers)) if numbers else None,
            "avg": _shrink(sum(numbers) / len(numbers)) if numbers else None,
            "sum": _shrink(sum(numbers)) if numbers else 0,
        }
    if not numbers:
        # ES returns null for min/max/avg over no documents, and 0 for sum.
        return {"value": 0 if agg_type == "sum" else None}
    if agg_type == "sum":
        return {"value": _shrink(sum(numbers))}
    if agg_type == "avg":
        return {"value": _shrink(sum(numbers) / len(numbers))}
    if agg_type == "min":
        return {"value": _shrink(min(numbers))}
    return {"value": _shrink(max(numbers))}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INTERVAL_UNITS = {
    "s": 1, "m": 60, "h": 3600, "H": 3600, "d": 86400, "w": 604800,
    "M": 2592000, "q": 7776000, "y": 31536000,
}


def _interval_seconds(interval: str) -> float:
    text = str(interval).strip()
    if not text:
        return 86400.0
    unit = text[-1]
    amount = text[:-1] or "1"
    try:
        return float(amount) * _INTERVAL_UNITS.get(unit, 86400)
    except ValueError:
        return 86400.0


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_epoch(value: Any) -> float | None:
    """Read a date field as epoch seconds, accepting ISO-8601 or a number."""
    number = _as_float(value)
    if number is not None:
        # Values in the millisecond range are epoch millis.
        return number / 1000 if number > 1e11 else number
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return None


def _in_range(value: float | None, lower: float | None, upper: float | None) -> bool:
    if value is None:
        return False
    if lower is not None and value < lower:
        return False
    return not (upper is not None and value >= upper)


def _range_key(lower: float | None, upper: float | None) -> str:
    left = "*" if lower is None else _render(lower)
    right = "*" if upper is None else _render(upper)
    return f"{left}-{right}"


def _render(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def _shrink(value: float) -> float | int:
    return int(value) if float(value).is_integer() else round(value, 6)
