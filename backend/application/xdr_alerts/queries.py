"""Cortex XDR Alert query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_alert_repo import xdr_alert_repo
from utils.serde import record_dict
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
    matched = apply_xdr_filters(
        xdr_alert_repo.list_all(), request_data.get("filters"), _ALERT_FILTER_FIELDS,
    )

    total = len(matched)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = [record_dict(r) for r in matched[search_from:search_to]]

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
            alerts.append(record_dict(alert))

    return build_xdr_list_reply(alerts, total_count=len(alerts), key="alerts")


#: The alert fields ``get_alerts_multi_events`` carries at the top level
#: (Elastic's transcription, ``xdr_alerts_multi_events_reduced.json``); the
#: per-event fields live under ``events``.
_MULTI_EVENT_TOP = frozenset({
    "action", "action_pretty", "alert_id", "category", "description",
    "detection_timestamp", "endpoint_id", "host_ip", "host_name",
    "is_whitelisted", "mitre_tactic_id_and_name", "mitre_technique_id_and_name",
    "name", "severity", "source", "starred",
})


def multi_events_alert(record: dict) -> dict:
    """A stored alert in the ``get_alerts_multi_events`` (v1) form.

    The alert keeps its own fields; what describes the triggering event —
    who, when, what kind — moves into the single item of ``events``. The
    route's fixture completes both to the transcribed shape.
    """
    alert = {k: v for k, v in record.items() if k in _MULTI_EVENT_TOP}
    alert["events"] = [
        {
            "event_type": record.get("event_type"),
            "event_timestamp": record.get("detection_timestamp"),
            "user_name": record.get("user_name"),
            "agent_host_boot_time": None,
        }
    ]
    return alert


def get_alerts_multi_events(request_data: dict) -> dict:
    """List alerts with their events, as the Splunk and Elastic integrations read them.

    Same filters and pagination as ``get_alerts_by_filter_data``.
    """
    matched = apply_xdr_filters(
        xdr_alert_repo.list_all(), request_data.get("filters"), _ALERT_FILTER_FIELDS,
    )
    total = len(matched)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = [multi_events_alert(record_dict(a)) for a in matched[search_from:search_to]]
    return build_xdr_list_reply(page, total_count=total, key="alerts")
