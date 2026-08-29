"""Read-side handlers for Microsoft Graph Security API."""
from __future__ import annotations

from application.mde_advanced_hunting.queries import run_query as run_hunt
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_orderby,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response
from utils.serde import record_dict
from utils.vendor_enums import graph_enum_order

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
    records = [record_dict(a) for a in graph_security_alert_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)
    # `$orderby` and `$select` were taken and dropped: a client that asked for
    # newest-first got insertion order, and one that asked for two fields got
    # the whole alert — believing both times that the query had been applied.
    records = apply_odata_orderby(records, orderby, graph_enum_order())

    total = len(records)
    page = apply_odata_select(records[skip : skip + top], select)
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
    return record_dict(alert)


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
    return record_dict(alert)


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
    records = [record_dict(inc) for inc in graph_security_incident_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    # Expand alerts if requested
    for rec in records:
        if expand and "alerts" in expand:
            rec["alerts"] = _expand_alerts(rec.get("alert_ids", []))
        rec.pop("alert_ids", None)

    records = apply_odata_orderby(records, orderby, graph_enum_order())
    total = len(records)
    page = apply_odata_select(records[skip : skip + top], select)
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

    result = record_dict(incident)
    if expand and "alerts" in expand:
        result["alerts"] = _expand_alerts(result.get("alert_ids", []))
    result.pop("alert_ids", None)

    return result


def _expand_alerts(alert_ids: list[str]) -> list[dict]:
    """Resolve alert IDs to full alert dicts for $expand=alerts."""
    alerts: list[dict] = []
    for aid in alert_ids:
        alert = graph_security_alert_repo.get(aid)
        if alert:
            alerts.append(record_dict(alert))
    return alerts


# ── Advanced Hunting ──────────────────────────────────────────────────────────

def run_hunting_query(body: dict) -> dict:
    """Execute a hunting query against the seeded hunting tables.

    Graph's advanced hunting is Defender's, and this mount had the
    implementation Defender's own route was given up: the query accepted and
    never evaluated, three synthetic rows returned whatever was asked, and
    device ids in them that this install does not have — so a hunter who
    followed a result to `managedDevices/{id}` got a 404 for a device the
    hunt had just reported. It runs the same evaluator over the same tables
    now, and answers in the envelope this mount already answered in.

    Args:
        body: Request body containing ``Query`` (a KQL string).

    Returns:
        Hunting response with ``Schema``, ``Results`` and ``Stats``.

    Raises:
        KqlError: If the query cannot be parsed or names an unknown table.
    """
    return run_hunt(body)



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
    records = [record_dict(s) for s in graph_secure_score_repo.list_all()]

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
