"""Cortex XDR Incident query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_alert_repo import xdr_alert_repo
from repository.xdr_incident_repo import xdr_incident_repo
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply


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
    all_incidents = [asdict(i) for i in xdr_incident_repo.list_all()]

    filters = request_data.get("filters", [])
    for f in filters:
        field = f.get("field", "")
        value = f.get("value")
        if field == "severity" and value:
            values = value if isinstance(value, list) else [value]
            all_incidents = [i for i in all_incidents if i["severity"] in values]
        elif field == "status" and value:
            values = value if isinstance(value, list) else [value]
            all_incidents = [i for i in all_incidents if i["status"] in values]
        elif field == "creation_time":
            gte = f.get("gte")
            lte = f.get("lte")
            if gte is not None:
                all_incidents = [i for i in all_incidents if i["creation_time"] >= gte]
            if lte is not None:
                all_incidents = [i for i in all_incidents if i["creation_time"] <= lte]

    total = len(all_incidents)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_incidents[search_from:search_to]

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
        "incident": asdict(incident),
        "alerts": {"total_count": len(linked_alerts), "data": [asdict(a) for a in linked_alerts]},
        "network_artifacts": {"total_count": len(network_artifacts), "data": network_artifacts},
        "file_artifacts": {"total_count": 0, "data": []},
    })
