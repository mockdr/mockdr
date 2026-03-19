"""Read-side handlers for Microsoft Graph Security API."""
from __future__ import annotations

from dataclasses import asdict

from domain.graph.ti_indicator import GraphTiIndicator
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from repository.graph.ti_indicator_repo import graph_ti_indicator_repo
from utils.dt import utc_now
from utils.graph_odata import apply_graph_filter
from utils.graph_response import build_graph_list_response

# ── Alerts v2 ─────────────────────────────────────────────────────────────────

def list_alerts_v2(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
) -> dict:
    """Return security alerts v2 with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     OData ``$select`` expression.

    Returns:
        OData list response dict.
    """
    records = [asdict(a) for a in graph_security_alert_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/security/alerts_v2?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2",
        next_link=next_link,
    )


def get_alert_v2(alert_id: str) -> dict | None:
    """Return a single security alert v2 by ID.

    Args:
        alert_id: The alert's ``id``.

    Returns:
        Alert dict or ``None`` if not found.
    """
    alert = graph_security_alert_repo.get(alert_id)
    if alert is None:
        return None
    return asdict(alert)


def update_alert_v2(alert_id: str, body: dict) -> dict | None:
    """Update a security alert v2 (status, assignedTo, classification, determination).

    Args:
        alert_id: The alert's ``id``.
        body:     Dict of fields to update.

    Returns:
        Updated alert dict or ``None`` if not found.
    """
    alert = graph_security_alert_repo.get(alert_id)
    if alert is None:
        return None

    updatable_fields = {"status", "assignedTo", "classification", "determination"}
    for field_name in updatable_fields:
        if field_name in body:
            setattr(alert, field_name, body[field_name])

    graph_security_alert_repo.save(alert)
    return asdict(alert)


# ── Incidents ─────────────────────────────────────────────────────────────────

def list_incidents(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    expand: str | None = None,
) -> dict:
    """Return security incidents with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     OData ``$select`` expression.
        expand:     OData ``$expand`` expression (supports ``alerts``).

    Returns:
        OData list response dict.
    """
    records = [asdict(inc) for inc in graph_security_incident_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    # Expand alerts if requested
    if expand and "alerts" in expand:
        for rec in records:
            rec["alerts"] = _expand_alerts(rec.get("alert_ids", []))

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/security/incidents?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/incidents",
        next_link=next_link,
    )


def get_incident(
    incident_id: str,
    expand: str | None = None,
) -> dict | None:
    """Return a single security incident by ID.

    Args:
        incident_id: The incident's ``id``.
        expand:      OData ``$expand`` expression (supports ``alerts``).

    Returns:
        Incident dict or ``None`` if not found.
    """
    incident = graph_security_incident_repo.get(incident_id)
    if incident is None:
        return None

    result = asdict(incident)
    if expand and "alerts" in expand:
        result["alerts"] = _expand_alerts(result.get("alert_ids", []))

    return result


def _expand_alerts(alert_ids: list[str]) -> list[dict]:
    """Resolve alert IDs to full alert dicts for $expand=alerts."""
    alerts: list[dict] = []
    for aid in alert_ids:
        alert = graph_security_alert_repo.get(aid)
        if alert:
            alerts.append(asdict(alert))
    return alerts


# ── Advanced Hunting ──────────────────────────────────────────────────────────

def run_hunting_query(body: dict) -> dict:
    """Execute a hunting query and return canned results.

    The real Graph Security Advanced Hunting API accepts a KQL query and
    returns a schema + results structure.  This mock returns synthetic data
    regardless of the query content.

    Args:
        body: Request body containing ``Query`` (KQL string).

    Returns:
        Hunting query response with ``schema`` and ``results`` arrays.
    """
    _query = body.get("Query", "")  # accepted but not evaluated
    now = utc_now()

    schema = [
        {"Name": "Timestamp", "Type": "DateTime"},
        {"Name": "DeviceId", "Type": "String"},
        {"Name": "DeviceName", "Type": "String"},
        {"Name": "ActionType", "Type": "String"},
        {"Name": "FileName", "Type": "String"},
        {"Name": "FolderPath", "Type": "String"},
        {"Name": "SHA256", "Type": "String"},
        {"Name": "InitiatingProcessFileName", "Type": "String"},
        {"Name": "InitiatingProcessCommandLine", "Type": "String"},
        {"Name": "AccountName", "Type": "String"},
    ]

    results = [
        {
            "Timestamp": now,
            "DeviceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "DeviceName": "ws-fin-001.acmecorp.internal",
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
            "SHA256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
            "InitiatingProcessFileName": "cmd.exe",
            "InitiatingProcessCommandLine": "cmd.exe /c powershell.exe -ep bypass",
            "AccountName": "jsmith",
        },
        {
            "Timestamp": now,
            "DeviceId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "DeviceName": "srv-dc-01.acmecorp.internal",
            "ActionType": "ConnectionSuccess",
            "FileName": "",
            "FolderPath": "",
            "SHA256": "",
            "InitiatingProcessFileName": "svchost.exe",
            "InitiatingProcessCommandLine": "svchost.exe -k netsvcs",
            "AccountName": "SYSTEM",
        },
        {
            "Timestamp": now,
            "DeviceId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
            "DeviceName": "ws-hr-042.acmecorp.internal",
            "ActionType": "FileCreated",
            "FileName": "suspicious_payload.exe",
            "FolderPath": "C:\\Users\\ajones\\Downloads",
            "SHA256": "abc123def456789012345678901234567890123456789012345678901234abcd",
            "InitiatingProcessFileName": "chrome.exe",
            "InitiatingProcessCommandLine": "chrome.exe --no-sandbox",
            "AccountName": "ajones",
        },
    ]

    return {
        "Schema": schema,
        "Results": results,
        "Stats": {
            "ExecutionTime": 0.031,
            "resource_usage": {
                "cache": {"memory": {"hits": 0, "misses": 1, "total": 1}},
                "cpu": {
                    "user": "00:00:00.0156250",
                    "kernel": "00:00:00",
                    "total cpu": "00:00:00.0156250",
                },
                "memory": {"peak_per_node": 1048576},
            },
            "dataset_statistics": [{"table_row_count": len(results), "table_size": 1024}],
        },
    }


# ── Secure Scores ─────────────────────────────────────────────────────────────

def list_secure_scores(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return secure score snapshots with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(s) for s in graph_secure_score_repo.list_all()]

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/security/secureScores?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/secureScores",
        next_link=next_link,
    )


# ── TI Indicators ────────────────────────────────────────────────────────────

def list_ti_indicators(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return threat intelligence indicators with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(ti) for ti in graph_ti_indicator_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/security/tiIndicators?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/tiIndicators",
        next_link=next_link,
    )


def create_ti_indicator(body: dict) -> dict:
    """Create a new TI indicator.

    Args:
        body: Dict with indicator fields.

    Returns:
        Created indicator dict.
    """
    from infrastructure.seeders.graph.graph_shared import graph_uuid

    indicator_id = graph_uuid()
    now = utc_now()

    ti = GraphTiIndicator(
        id=indicator_id,
        action=body.get("action", "alert"),
        description=body.get("description", ""),
        expirationDateTime=body.get("expirationDateTime", ""),
        targetProduct=body.get("targetProduct", "Microsoft Defender ATP"),
        threatType=body.get("threatType", "Malware"),
        tlpLevel=body.get("tlpLevel", "green"),
        indicatorValue=body.get("indicatorValue", ""),
        indicatorType=body.get("indicatorType", ""),
        createdDateTime=now,
        lastReportedDateTime=now,
    )
    graph_ti_indicator_repo.save(ti)
    return asdict(ti)


def delete_ti_indicator(indicator_id: str) -> bool:
    """Delete a TI indicator by ID.

    Args:
        indicator_id: The indicator's ``id``.

    Returns:
        ``True`` if deleted, ``False`` if not found.
    """
    existing = graph_ti_indicator_repo.get(indicator_id)
    if existing is None:
        return False
    graph_ti_indicator_repo.delete(indicator_id)
    return True
