"""Cortex XDR Alert query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_alert_repo import xdr_alert_repo
from utils.xdr_filters import apply_xdr_filters
from utils.xdr_response import build_xdr_list_reply

#: Filter fields this endpoint supports, mapped to the stored record key.
#: Only severity, alert_source and creation_time used to be read; every other
#: field — category, action, incident_id — was accepted and ignored, so a
#: filtered request returned the whole alert set.
_ALERT_FILTER_FIELDS: dict[str, str] = {
    "alert_id_list": "alert_id",
    "alert_source": "source",
    "severity": "severity",
    "creation_time": "detection_timestamp",
    "category": "category",
    "action": "alert_action_status",
    "incident_id": "incident_id",
    "endpoint_id_list": "endpoint_id",
    "hostname": "host_name",
    "username": "user_name",
    "alert_name": "name",
    "description": "description",
    "event_type": "event_type",
    "starred": "starred",
    "mitre_technique_id_and_name": "mitre_technique_id_and_name",
    "mitre_tactic_id_and_name": "mitre_tactic_id_and_name",
}



def get_alerts(request_data: dict) -> dict:
    """List alerts with optional filtering and pagination.

    Supports filters on ``severity``, ``alert_source``, and ``creation_time``
    range.  Pagination via ``search_from`` and ``search_to``.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching alerts.
    """
    all_alerts = [asdict(a) for a in xdr_alert_repo.list_all()]

    all_alerts = apply_xdr_filters(
        all_alerts, request_data.get("filters"), _ALERT_FILTER_FIELDS,
    )

    total = len(all_alerts)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_alerts[search_from:search_to]

    return build_xdr_list_reply(page, total_count=total, key="alerts")


def get_original_alerts(alert_ids: list[str]) -> dict:
    """Return full alert data for specific alert IDs.

    Args:
        alert_ids: List of alert identifiers to retrieve.

    Returns:
        XDR list reply with matching alerts.
    """
    alerts = []
    for aid in alert_ids:
        alert = xdr_alert_repo.get(aid)
        if alert:
            alerts.append(asdict(alert))

    return build_xdr_list_reply(alerts, total_count=len(alerts), key="alerts")
