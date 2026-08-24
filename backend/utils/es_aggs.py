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
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

from utils.es_datemath import _add_months, _next_unit, _round_down
from utils.es_datemath import _zone as _datemath_zone
from utils.es_query import build_predicate, wrap_as_hits
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

    def __init__(
        self, message: str, *, clause: str | None = None,
        es_type: str = "parsing_exception",
    ) -> None:
        """Record the message, the clause if any, and the exception type.

        ``x_content_parse_exception`` is how Elasticsearch reports a field the
        aggregation does not have; it carries its position inside the reason
        text rather than as separate members, and no cause.
        """
        super().__init__(message)
        self.clause = clause
        self.es_type = es_type



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
        raise ESAggregationError(msg, clause=name)
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
    raise ESAggregationError(msg, clause=agg_type)


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
        matches = build_predicate(body)  # compiled once, not once per document
        matched = [r for r in records if matches(r)]
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
    """Bucket by time, filling the gaps the way Elasticsearch does.

    Two things were wrong here and both showed up as a broken chart rather
    than an error. Intervals with no documents were left out entirely, so a
    series plotted from the response jumped over quiet days instead of
    drawing them at zero — Elasticsearch emits every bucket between the first
    and the last unless ``min_doc_count`` says otherwise. And a calendar
    interval was treated as a fixed number of seconds, so ``1M`` meant 30 days
    and ``1w`` weeks that began on a Thursday, because that is the weekday the
    epoch fell on.
    """
    field = body.get("field", "")
    zone = _zone(body.get("time_zone"))
    calendar_unit, fixed = _interval_plan(body)
    min_doc_count = int(body.get("min_doc_count", 0))

    groups: dict[datetime, list[dict]] = {}
    for record in records:
        stamp = _as_epoch(get_nested(record, field))
        if stamp is None:
            continue
        start = _bucket_start(stamp, calendar_unit, fixed, zone)
        groups.setdefault(start, []).append(record)

    buckets = []
    for start in _bucket_starts(sorted(groups), calendar_unit, fixed, min_doc_count):
        members = groups.get(start, [])
        bucket = {
            "key": int(start.timestamp() * 1000),
            "key_as_string": _es_timestamp(start),
            "doc_count": len(members),
        }
        buckets.append(_with_sub(bucket, sub, members, index, depth))
    return {"buckets": buckets}


def _bucket_starts(
    populated: list[datetime],
    calendar_unit: str | None,
    fixed: float,
    min_doc_count: int,
) -> list[datetime]:
    """Every bucket the response should carry, in order.

    With the default ``min_doc_count`` of 0 that is every interval from the
    first populated bucket to the last, empty ones included.
    """
    if min_doc_count > 0 or len(populated) < 2:
        return populated
    starts = [populated[0]]
    last = populated[-1]
    # A pathological interval against a wide span would otherwise build an
    # unbounded list; Elasticsearch caps buckets too (search.max_buckets).
    while starts[-1] < last and len(starts) < _MAX_BUCKETS:
        starts.append(_next_bucket(starts[-1], calendar_unit, fixed))
    return starts


#: Elasticsearch's search.max_buckets default, which bounds the same list.
_MAX_BUCKETS = 65_536


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
            {"key": float(start), "doc_count": len(groups[start])},
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
    # The predicate is compiled once per clause, not once per document: it sat
    # inside the comprehension's condition, so a bucket over ten thousand
    # documents rebuilt the same matcher ten thousand times.
    if isinstance(named, dict):
        buckets: dict[str, Any] = {}
        for key, clause in named.items():
            matches = build_predicate(clause)
            members = [r for r in records if matches(r)]
            buckets[key] = _with_sub(
                {"doc_count": len(members)}, sub, members, index, depth,
            )
        return {"buckets": buckets}

    anonymous = []
    for clause in named:
        matches = build_predicate(clause)
        members = [r for r in records if matches(r)]
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
    # Every numeric metric is a double in Elasticsearch, so an average that
    # happens to divide evenly still comes back as `30.0`. Rendering it as
    # `30` made the mock's JSON a different document from the real one, and
    # a strictly-typed client reads that as a different type.
    if agg_type == "stats":
        return {
            "count": len(numbers),
            "min": min(numbers) if numbers else None,
            "max": max(numbers) if numbers else None,
            "avg": sum(numbers) / len(numbers) if numbers else None,
            "sum": float(sum(numbers)) if numbers else 0.0,
        }
    if not numbers:
        # ES returns null for min/max/avg over no documents, and 0 for sum.
        return {"value": 0.0 if agg_type == "sum" else None}
    if agg_type == "sum":
        return {"value": float(sum(numbers))}
    if agg_type == "avg":
        return {"value": sum(numbers) / len(numbers)}
    if agg_type == "min":
        return {"value": min(numbers)}
    return {"value": max(numbers)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INTERVAL_UNITS = {
    "s": 1, "m": 60, "h": 3600, "H": 3600, "d": 86400, "w": 604800,
    "M": 2592000, "q": 7776000, "y": 31536000,
}

#: The spellings a calendar interval takes; only a multiple of one is allowed,
#: which is what separates ``calendar_interval`` from ``fixed_interval``.
_CALENDAR_UNITS: dict[str, str] = {
    "s": "s", "second": "s", "1s": "s",
    "m": "m", "minute": "m", "1m": "m",
    "h": "h", "hour": "h", "1h": "h",
    "d": "d", "day": "d", "1d": "d",
    "w": "w", "week": "w", "1w": "w",
    "M": "M", "month": "M", "1M": "M",
    "q": "q", "quarter": "q", "1q": "q",
    "y": "y", "year": "y", "1y": "y",
}


def _interval_seconds(interval: str) -> float:
    """A fixed interval as a span of seconds."""
    text = str(interval).strip()
    if not text:
        return 86400.0
    unit = text[-1]
    amount = text[:-1] or "1"
    try:
        return float(amount) * _INTERVAL_UNITS.get(unit, 86400)
    except ValueError:
        return 86400.0


def _interval_plan(body: dict) -> tuple[str | None, float]:
    """Read the interval as either a calendar unit or a fixed span of seconds.

    Returns:
        ``(calendar_unit, fixed_seconds)`` — exactly one is meaningful.
    """
    if "interval" in body and not (body.get("calendar_interval") or body.get("fixed_interval")):
        # Removed in Elasticsearch 8: a body still sending it is refused, not
        # read as a calendar interval. Accepting it here would let a client
        # keep an interval the real cluster rejects.
        msg = "[date_histogram] unknown field [interval] did you mean [fixed_interval]?"
        raise ESAggregationError(
            msg, clause="interval", es_type="x_content_parse_exception",
        )
    calendar = body.get("calendar_interval")
    if calendar:
        unit = _CALENDAR_UNITS.get(str(calendar).strip())
        if unit:
            return unit, 0.0
        return None, _interval_seconds(calendar)
    fixed = body.get("fixed_interval")
    if fixed:
        return None, _interval_seconds(fixed)
    # Neither given: Elasticsearch's own default bucketing.
    return "d", 0.0


def _zone(time_zone: str | None) -> tzinfo:
    """The zone bucket boundaries fall in; UTC unless the request says otherwise."""
    return _datemath_zone(time_zone)


def _bucket_start(
    stamp: float, calendar_unit: str | None, fixed: float, zone: tzinfo,
) -> datetime:
    """The start of the bucket *stamp* belongs to."""
    if calendar_unit is None:
        # A fixed interval is anchored on the epoch, not on the data.
        span = fixed or 86400.0
        return datetime.fromtimestamp((stamp // span) * span, tz=UTC)
    moment = datetime.fromtimestamp(stamp, tz=UTC).astimezone(zone)
    if calendar_unit == "q":
        return moment.replace(
            month=(moment.month - 1) // 3 * 3 + 1, day=1,
            hour=0, minute=0, second=0, microsecond=0,
        )
    return _round_down(moment, calendar_unit)


def _next_bucket(start: datetime, calendar_unit: str | None, fixed: float) -> datetime:
    """The start of the bucket after *start*."""
    if calendar_unit is None:
        return start + timedelta(seconds=fixed or 86400.0)
    if calendar_unit == "q":
        return _add_months(start, 3)
    return _next_unit(start, calendar_unit)


def _es_timestamp(moment: datetime) -> str:
    """Render a bucket key the way Elasticsearch renders ``key_as_string``.

    ``2026-08-01T00:00:00.000Z`` in UTC, and local time with its offset when
    the request named a zone. ``datetime.isoformat`` writes ``+00:00`` and no
    milliseconds, so a client parsing the string with a strict format failed
    on every bucket.
    """
    base = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}"
    offset = moment.utcoffset() or timedelta(0)
    if not offset:
        return base + "Z"
    total = int(offset.total_seconds())
    sign = "+" if total >= 0 else "-"
    return f"{base}{sign}{abs(total) // 3600:02d}:{abs(total) % 3600 // 60:02d}"


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
    """A range bound as it appears in the bucket key — always a double."""
    return str(float(value))
