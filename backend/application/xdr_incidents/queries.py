"""Cortex XDR Incident query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_alert_repo import xdr_alert_repo
from repository.xdr_incident_repo import xdr_incident_repo
from utils.serde import record_dict
from utils.xdr_filters import apply_xdr_filters, apply_xdr_sort
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply

#: The filter fields Cortex XDR documents for this route, as the XSOAR
#: integration sends them. A field outside this map is an error rather than a
#: silent pass-through: `incident_id_list` used to be ignored, and a client
#: asking for one incident received all of them.
_INCIDENT_FILTER_FIELDS: dict[str, str] = {
    "incident_id_list": "incident_id",
    "status": "status",
    "severity": "severity",
    "starred": "starred",
    "creation_time": "creation_time",
    "modification_time": "modification_time",
    "description": "description",
    "alert_count": "alert_count",
    "assigned_user_mail": "assigned_user_mail",
    "assigned_user_pretty_name": "assigned_user_pretty_name",
}


def get_incidents(request_data: dict) -> dict:
    """List incidents with optional filtering and pagination.

    Supports filters on ``severity``, ``status``, and ``creation_time``
    range (``creation_time_from`` / ``creation_time_to``).  Pagination
    via ``search_from`` and ``search_to``.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching incidents.
    """
    matched = apply_xdr_filters(
        xdr_incident_repo.list_all(), request_data.get("filters"), _INCIDENT_FILTER_FIELDS,
    )
    matched = apply_xdr_sort(matched, request_data.get("sort"))

    total = len(matched)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = [record_dict(r) for r in matched[search_from:search_to]]

    return build_xdr_list_reply(page, total_count=total, key="incidents")


def get_incident_extra_data(incident_id: str) -> dict | None:
    """Return an incident with its linked alerts and network artifacts.

    Args:
        incident_id: The incident identifier.

    Returns:
        XDR reply with incident detail, linked alerts, and network artifacts,
        or None if incident not found.
    """
    incident = xdr_incident_repo.get(incident_id)
    if not incident:
        return None

    linked_alerts = xdr_alert_repo.get_by_incident_id(incident_id)

    network_artifacts = []
    for alert in linked_alerts:
        for ip in alert.host_ip:
            network_artifacts.append({
                "type": "ip",
                "alert_count": 1,
                "is_manual": False,
                "network_remote_ip": ip,
                "network_country": "US",
            })

    return build_xdr_reply({
        "incident": record_dict(incident),
        "alerts": {
            "total_count": len(linked_alerts),
            "data": [record_dict(a) for a in linked_alerts],
        },
        "network_artifacts": {"total_count": len(network_artifacts), "data": network_artifacts},
        "file_artifacts": {"total_count": 0, "data": []},
    })
