"""Sentinel Log Analytics KQL query handler."""
from __future__ import annotations

from domain.sentinel.alert import SentinelAlert
from domain.sentinel.incident import SentinelIncident
from repository.sentinel.alert_repo import sentinel_alert_repo
from repository.sentinel.incident_repo import sentinel_incident_repo
from utils.sentinel.kql_parser import parse_kql
from utils.sentinel.response import build_log_analytics_response

# Table name → (fetch_fn, column_mapping)
_TABLE_REGISTRY: dict[str, tuple] = {}


def query_logs(kql: str) -> dict:
    """Execute a KQL query against the mock Log Analytics tables.

    Args:
        kql: KQL query string.

    Returns:
        Log Analytics response dict with tables/columns/rows.
    """
    parsed = parse_kql(kql)
    rows: list[dict] = []

    for table in parsed.tables:
        rows.extend(_get_table_data(table))

    # Apply where clauses
    for field_name, op, value in parsed.where_clauses:
        rows = _filter_rows(rows, field_name, op, value)

    # Apply where in clauses
    for field_name, values in parsed.where_in_clauses:
        rows = [r for r in rows if str(r.get(field_name, "")) in values]

    # Apply ago filters
    for field_name, threshold in parsed.ago_filters:
        rows = [r for r in rows if _parse_time(r.get(field_name, "")) > threshold]

    # Apply summarize
    if parsed.summarize_func == "count" and parsed.summarize_by:
        return _summarize_count(rows, parsed.summarize_by)

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

    # Custom log tables (SentinelOne_CL, CrowdStrike_CL, etc.)
    # Return empty for now — these are populated by the Splunk event store
    return []


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


def _filter_rows(rows: list[dict], field: str, op: str, value: str) -> list[dict]:
    """Apply a comparison filter to rows."""
    result = []
    for r in rows:
        row_val = str(r.get(field, ""))
        if op == "==" and row_val == value:
            result.append(r)
        elif op == "!=" and row_val != value:
            result.append(r)
        elif op == ">" and row_val > value:
            result.append(r)
        elif op == "<" and row_val < value:
            result.append(r)
        elif op == ">=" and row_val >= value:
            result.append(r)
        elif op == "<=" and row_val <= value:
            result.append(r)
    return result


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
