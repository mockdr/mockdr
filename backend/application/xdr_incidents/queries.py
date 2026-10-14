"""Cortex XDR Incident query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_alert_repo import xdr_alert_repo
from repository.xdr_incident_repo import xdr_incident_repo
from utils.serde import record_dict
from utils.xdr_filters import apply_xdr_filters, apply_xdr_sort
from utils.xdr_response import XDR_MAX_PAGE, build_xdr_list_reply, build_xdr_reply, page_bounds

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
    search_from, search_to = page_bounds(request_data, XDR_MAX_PAGE)
    page = [record_dict(r) for r in matched[search_from:search_to]]

    return build_xdr_list_reply(page, total_count=total, key="incidents")


def _extra_data(incident: object, alerts_limit: int | None = None) -> dict:
    """One incident with its linked alerts and artifacts, as extra-data serves it."""
    incident_id = str(getattr(incident, "incident_id", ""))
    linked_alerts = xdr_alert_repo.get_by_incident_id(incident_id)

    network_artifacts = []
    for alert in linked_alerts:
        for ip in alert.host_ip:
            # Spelled as the recorded artifacts are: upper-case `type`, and
            # the domain and port members present even when unknown.
            network_artifacts.append({
                "type": "IP",
                "alert_count": 1,
                "is_manual": False,
                "network_domain": None,
                "network_remote_ip": ip,
                "network_remote_port": None,
                "network_country": "US",
            })

    shown = linked_alerts if alerts_limit is None else linked_alerts[:alerts_limit]
    return {
        "incident": record_dict(incident),
        "alerts": {
            "total_count": len(linked_alerts),
            "data": [_extra_data_alert(record_dict(a)) for a in shown],
        },
        "network_artifacts": {"total_count": len(network_artifacts), "data": network_artifacts},
        "file_artifacts": {"total_count": 0, "data": []},
    }


def _extra_data_alert(record: dict) -> dict:
    """An alert as extra-data lists it: ``host_ip`` one comma-separated string.

    Every recorded extra-data reply spells it that way -- ``"1.1.1.1"``,
    ``"1.1.1.1, 2.2.2.2"`` for a host with two, null when unknown (XSOAR
    test_data ``get_incident_extra_data.json``,
    ``get_incident_extra_data_host_id_array.json``,
    ``get_multiple_incidents_extra_data.json``) -- and the XSOAR integration
    depends on it: ``sort_incident_data`` builds ``host_ip_list`` with
    ``alert.get("host_ip").split(",")``. The mock kept the list it stores, so
    every ``fetch-incidents`` cycle raised ``AttributeError: 'list' object has
    no attribute 'split'`` on the first incident with an alert.
    """
    ips = record.get("host_ip")
    if isinstance(ips, list):
        record = {**record, "host_ip": ", ".join(str(ip) for ip in ips) or None}
    return record


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
    return build_xdr_reply(_extra_data(incident))


#: How many alerts each incident carries in a multi-incident reply. The XSOAR
#: integration reads it back from `alerts_limit_per_incident` and documents it
#: as 50 (CortexXDRIR `Client.get_multiple_incidents_extra_data`).
ALERTS_LIMIT_PER_INCIDENT = 50

#: The artifact lists `fields_to_exclude` may drop — what the XSOAR client
#: sends for `exclude_artifacts` (CortexXDRIR `FIELDS_TO_EXCLUDE`). The
#: recorded reply shape then answers them empty.
_EXCLUDABLE = ("network_artifacts", "file_artifacts")


def get_multiple_incidents_extra_data(request_data: dict) -> dict:
    """Several incidents, each with its alerts and artifacts, in one call.

    The XSOAR integration fetches incidents through this route
    (`/incidents/get_multiple_incidents_extra_data/`), with the same
    `filters`, `sort`, `search_from` and `search_to` as `get_incidents`. Its
    recorded reply (test_data get_multiple_incidents_extra_data.json) is
    `{total_count, result_count, alerts_limit_per_incident, incidents: [{incident,
    alerts, network_artifacts, file_artifacts}]}`.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR reply with the page of incidents and their extra data.
    """
    matched = apply_xdr_filters(
        xdr_incident_repo.list_all(), request_data.get("filters"), _INCIDENT_FILTER_FIELDS,
    )
    matched = apply_xdr_sort(matched, request_data.get("sort"))

    search_from, search_to = page_bounds(request_data, XDR_MAX_PAGE)
    excluded = request_data.get("fields_to_exclude") or []
    items = []
    for incident in matched[search_from:search_to]:
        item = _extra_data(incident, ALERTS_LIMIT_PER_INCIDENT)
        for name in _EXCLUDABLE:
            if isinstance(excluded, list) and name in excluded:
                item.pop(name)
        items.append(item)

    return build_xdr_reply({
        "total_count": len(matched),
        "result_count": len(items),
        "alerts_limit_per_incident": ALERTS_LIMIT_PER_INCIDENT,
        "incidents": items,
    })
