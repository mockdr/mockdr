"""Sentinel Log Analytics KQL query handler."""
from __future__ import annotations

import re
from datetime import UTC, datetime

from domain.sentinel.alert import SentinelAlert
from domain.sentinel.incident import SentinelIncident
from repository.sentinel.alert_repo import sentinel_alert_repo
from repository.sentinel.incident_repo import sentinel_incident_repo
from repository.splunk.splunk_event_repo import splunk_event_repo
from utils.sentinel.kql_parser import UnsupportedKqlError, parse_kql
from utils.sentinel.response import build_log_analytics_response

# Table name → (fetch_fn, column_mapping)
_TABLE_REGISTRY: dict[str, tuple] = {}

#: The custom tables this workspace's own data connectors advertise, and the
#: events each one ingests. `dataConnectors` publishes the table name *and*
#: the query a client runs against it — `SentinelOne_CL | summarize
#: max(TimeGenerated)` — and every one of them answered an empty table, so a
#: client that read the connector list and ran the query it was given
#: learned that a connector this workspace says is ingesting has ingested
#: nothing.
#: How each connector's table is spelled where a client writes it.
_ADVERTISED: tuple[str, ...] = (
    "SentinelOne_CL",
    "CrowdStrikeFalcon_CL",
    "ElasticSecurity_CL",
    "PaloAltoCortexXDR_CL",
)

_CUSTOM_TABLES: dict[str, tuple[str, ...]] = {
    "sentinelone_cl": ("sentinelone:",),
    "crowdstrikefalcon_cl": ("CrowdStrike:",),
    "elasticsecurity_cl": ("elastic:",),
    "paloaltocortexxdr_cl": ("pan:xdr:",),
}


class UnknownTableError(ValueError):
    """A table this workspace does not have, named by a query."""


#: The tables this workspace answers for. A query naming anything else is an
#: error, the way Defender's hunting already refuses one here — answering
#: `200` with no rows told a client "nothing matched" when the truth was
#: "there is no such table", and a mistyped connector name looked like a
#: quiet day.
def table_names() -> tuple[str, ...]:
    """Every table a query may name, in the spelling the connectors use."""
    return ("SecurityIncident", "SecurityAlert", *_ADVERTISED)


def query_logs(kql: str) -> dict:
    """Execute a KQL query against the mock Log Analytics tables.

    Args:
        kql: KQL query string.

    Returns:
        Log Analytics response dict with tables/columns/rows.
    """
    parsed = parse_kql(kql)
    rows: list[dict] = []

    # The table is resolved before an unreadable clause is refused: a query
    # naming a table this workspace does not have is wrong in a way the
    # client can fix, and saying so first is more use than complaining about
    # a pipeline that would never have run anyway.
    for table in parsed.tables:
        rows.extend(_get_table_data(table))

    if parsed.unsupported:
        raise UnsupportedKqlError(parsed.unsupported)

    # Apply where clauses
    for field_name, op, value in parsed.where_clauses:
        rows = _filter_rows(rows, field_name, op, value)

    # Apply where in clauses
    for field_name, values in parsed.where_in_clauses:
        rows = [r for r in rows if str(r.get(field_name, "")) in values]
    for field_name, values in parsed.where_not_in_clauses:
        rows = [r for r in rows if str(r.get(field_name, "")) not in values]

    # Apply ago filters
    for field_name, threshold in parsed.ago_filters:
        rows = [r for r in rows if _parse_time(r.get(field_name, "")) > threshold]

    # `| count` is one row with the number that reached it.
    if parsed.count_only:
        return build_log_analytics_response(
            [{"name": "Count", "type": "int"}], [[len(rows)]])

    # `| distinct a, b` reduces to those columns and drops repeats, keeping
    # the order they were first seen in — it answered the whole table before.
    if parsed.distinct_fields:
        seen: set[tuple[str, ...]] = set()
        reduced: list[list[str]] = []
        for row in rows:
            key = tuple(str(row.get(f, "")) for f in parsed.distinct_fields)
            if key not in seen:
                seen.add(key)
                reduced.append(list(key))
        if parsed.take > 0:
            reduced = reduced[:parsed.take]
        return build_log_analytics_response(
            [{"name": f, "type": "string"} for f in parsed.distinct_fields], reduced,
        )

    # Apply summarize
    if parsed.summarize_func == "count" and parsed.summarize_by:
        return _summarize_count(rows, parsed.summarize_by)
    if parsed.summarize_func in ("max", "min") and parsed.summarize_field:
        return _summarize_extreme(
            rows, parsed.summarize_field, parsed.summarize_func)

    # Apply sort
    if parsed.sort_field:
        rows.sort(
            key=lambda r: str(r.get(parsed.sort_field, "")),
            reverse=parsed.sort_descending,
        )

    # Apply take/limit
    if parsed.take > 0:
        rows = rows[:parsed.take]

    # Apply project
    if parsed.project_fields:
        columns = [{"name": f, "type": "string"} for f in parsed.project_fields]
        result_rows = [[r.get(f, "") for f in parsed.project_fields] for r in rows]
        return build_log_analytics_response(columns, result_rows)

    # Default: return all fields
    if not rows:
        return build_log_analytics_response([], [])

    all_fields = list(rows[0].keys())
    columns = [{"name": f, "type": "string"} for f in all_fields]
    result_rows = [[r.get(f, "") for f in all_fields] for r in rows]
    return build_log_analytics_response(columns, result_rows)


def _get_table_data(table: str) -> list[dict]:
    """Get rows for a named Log Analytics table."""
    table_lower = table.lower()

    if table_lower == "securityincident":
        return [_incident_to_row(i) for i in sentinel_incident_repo.list_all()]
    if table_lower == "securityalert":
        return [_alert_to_row(a) for a in sentinel_alert_repo.list_all()]

    prefixes = _CUSTOM_TABLES.get(table_lower)
    if prefixes is not None:
        return [
            _event_to_row(event)
            for event in splunk_event_repo.list_all()
            if event.sourcetype.startswith(prefixes)
        ]

    msg = (
        f"Failed to resolve table or column expression named '{table}'. "
        f"Tables in this workspace: {', '.join(table_names())}"
    )
    raise UnknownTableError(msg)


def _event_to_row(event: object) -> dict:
    """One ingested event as a custom-log row.

    `TimeGenerated` is what every connector's own `lastDataReceivedQuery`
    summarises, and what a workspace orders its custom logs by; the rest are
    the fields the event carried in.
    """
    generated = datetime.fromtimestamp(
        getattr(event, "time", 0.0) or 0.0, tz=UTC,
    ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    row: dict = {
        "TimeGenerated": generated,
        "Computer": str(getattr(event, "host", "")),
        "SourceSystem": str(getattr(event, "sourcetype", "")),
    }
    for name, value in (getattr(event, "fields", {}) or {}).items():
        if isinstance(value, (str, int, float, bool)):
            row[str(name)] = value
    return row


def _incident_to_row(inc: SentinelIncident) -> dict:
    """Convert a SentinelIncident to a flat row dict."""
    return {
        "IncidentNumber": inc.incident_number,
        "Title": inc.title,
        "Description": inc.description,
        "Severity": inc.severity,
        "Status": inc.status,
        "Classification": inc.classification,
        "Owner": inc.owner_assigned_to,
        "CreatedTime": inc.created_time_utc,
        "LastModifiedTime": inc.last_modified_time_utc,
        "ProviderName": inc.provider_name,
        "AlertsCount": len(inc.alert_ids),
        "TimeGenerated": inc.created_time_utc,
    }


def _alert_to_row(alert: SentinelAlert) -> dict:
    """Convert a SentinelAlert to a flat row dict."""
    return {
        "AlertName": alert.alert_display_name,
        "Description": alert.description,
        "Severity": alert.severity,
        "Status": alert.status,
        "ProductName": alert.product_name,
        "ProviderName": alert.vendor_name,
        "VendorName": alert.vendor_name,
        "TimeGenerated": alert.time_generated,
        "Tactics": ", ".join(alert.tactics),
        "Techniques": ", ".join(alert.techniques),
    }


def _as_number(text: str) -> float | None:
    """`text` as a number, or None if it is not one."""
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _ordered(row_val: str, value: str, op: str) -> bool:
    """`<`, `>`, `<=`, `>=` — numerically where both sides are numbers.

    Compared as text, `event.Severity >= 3` kept "81" and dropped "100",
    because "1" sorts before "3".  Every severity in these tables is a
    number, so every threshold query was answering the wrong set.
    """
    left, right = _as_number(row_val), _as_number(value)
    if left is not None and right is not None:
        return _compare(left, right, op)
    return _compare(row_val, value, op)


def _compare(left: float | str, right: float | str, op: str) -> bool:
    """`left <op> right`, both sides already the same kind."""
    if op == ">":
        return left > right  # type: ignore[operator]
    if op == "<":
        return left < right  # type: ignore[operator]
    if op == ">=":
        return left >= right  # type: ignore[operator]
    return left <= right  # type: ignore[operator]


def _matches(row_val: str, op: str, value: str) -> bool:
    """One predicate against one row's value for the column it names."""
    folded, wanted = row_val.casefold(), value.casefold()
    if op == "==":
        return row_val == value
    if op == "!=":
        return row_val != value
    # `=~` and `!~` are KQL's case-insensitive equality.
    if op == "=~":
        return folded == wanted
    if op == "!~":
        return folded != wanted
    # KQL's string operators are case-insensitive; the `!` forms negate.
    if op == "contains":
        return wanted in folded
    if op == "!contains":
        return wanted not in folded
    if op == "startswith":
        return folded.startswith(wanted)
    if op == "!startswith":
        return not folded.startswith(wanted)
    if op == "endswith":
        return folded.endswith(wanted)
    if op == "!endswith":
        return not folded.endswith(wanted)
    # `has` matches a whole term, not a substring: "cmd" has-matches
    # "cmd.exe run" but not "cmdline".
    if op in ("has", "!has"):
        found = wanted in re.split(r"[^\w]+", folded)
        return found if op == "has" else not found
    return _ordered(row_val, value, op)


def _filter_rows(rows: list[dict], field: str, op: str, value: str) -> list[dict]:
    """Apply a comparison filter to rows."""
    return [r for r in rows if _matches(str(r.get(field, "")), op, value)]


def _summarize_count(rows: list[dict], by_field: str) -> dict:
    """Summarize count() by field."""
    counts: dict[str, int] = {}
    for r in rows:
        key = str(r.get(by_field, ""))
        counts[key] = counts.get(key, 0) + 1

    columns = [{"name": by_field, "type": "string"}, {"name": "count_", "type": "long"}]
    result_rows = [[k, v] for k, v in counts.items()]
    return build_log_analytics_response(columns, result_rows)


def _parse_time(val: object) -> float:
    """Try to parse a time value to epoch seconds."""
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str) and val:
        try:
            # ISO-8601
            import datetime
            dt = datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return 0.0



def _summarize_extreme(rows: list[dict], field_name: str, func: str) -> dict:
    """One row: the largest or smallest value of a field.

    Log Analytics names the column after the aggregate — `max_TimeGenerated`
    — which is what a client reading a connector's `lastDataReceivedQuery`
    looks for.
    """
    values = [str(r.get(field_name, "")) for r in rows if r.get(field_name)]
    best = (max(values) if func == "max" else min(values)) if values else None
    return build_log_analytics_response(
        [{"name": f"{func}_{field_name}", "type": "datetime"}], [[best]],
    )
