"""Cortex XDR Alert query handlers (read-only)."""
from __future__ import annotations

import json

from repository.xdr_alert_repo import xdr_alert_repo
from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.serde import record_dict
from utils.xdr_filter_data import apply_filter_data, filter_data_page, sort_filter_data
from utils.xdr_filters import XdrFilterError, apply_xdr_filters, apply_xdr_sort
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply, page_bounds

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



#: An alert's ``severity`` as ``alert_fields`` spells it (CoreIRApiModule
#: ``SEVERITY_STATUSES``; the recorded reply's ``SEV_030_MEDIUM``).
_SEVERITY_CODES = {
    "informational": "SEV_010_INFO", "low": "SEV_020_LOW", "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH", "critical": "SEV_050_CRITICAL",
}

#: The detection method's machine name, which ``alert_fields.alert_source``
#: carries (CoreIRApiModule ``DETECTION_METHOD_HR_TO_MACHINE_NAME``).
_SOURCE_CODES = {
    "XDR Agent": "TRAPS", "XDR Analytics": "MAGNIFIER", "XDR Analytics BIOC": "ANALYTICS_BIOC",
    "PAN NGFW": "FW", "XDR BIOC": "BIOC", "BIOC": "BIOC", "XDR IOC": "IOC", "IOC": "IOC",
    "Correlation": "CORRELATION", "Threat Intelligence": "THREAT_INTELLIGENCE",
}

_OS_CODES = {"windows": "AGENT_OS_WINDOWS", "linux": "AGENT_OS_LINUX", "macos": "AGENT_OS_MAC"}


def alert_fields(record: dict) -> dict:
    """A stored alert as ``get_alerts_by_filter_data`` lists it, in ``alert_fields``.

    The recorded reply (XSOAR test_data ``get_alerts_by_filter_results.json``)
    names an alert's members its own way -- ``internal_id``, ``alert_name``,
    ``alert_category``, ``alert_source`` as a detection-method code,
    ``severity`` as ``SEV_0x0_*``, ``source_insert_ts``, ``agent_id``,
    ``agent_ip_addresses`` -- and nests them under ``alert_fields``; the
    XSOAR integration reads nothing else (``alert.get("alert_fields")``).
    Beyond the recording's members it carries the ones the integration
    filters on or prints -- ``actor_effective_username`` and the MITRE pair
    are ``SEARCH_FIELD``s in ``init_filter_args_options``, ``agent_hostname``
    is the "Host Name" column of ``xdr-get-alerts``.
    """
    internal = str(record.get("internal_id") or "")
    endpoint = xdr_endpoint_repo.get(str(record.get("endpoint_id") or ""))
    timestamp = record.get("detection_timestamp")
    action = str(record.get("alert_action_status") or "")
    return {
        "internal_id": int(internal) if internal.isdigit() else internal,
        "external_id": record.get("alert_id"),
        "alert_source": _SOURCE_CODES.get(str(record.get("source")), record.get("source")),
        "matching_status": "MATCHED",
        "severity": _SEVERITY_CODES.get(str(record.get("severity")), record.get("severity")),
        "local_insert_ts": timestamp,
        "source_insert_ts": timestamp,
        "alert_name": record.get("name"),
        "alert_category": record.get("category"),
        "alert_description": record.get("description"),
        "bioc_indicator": None,
        "alert_action_status": action.upper() or None,
        "is_whitelisted": bool(record.get("is_whitelisted")),
        "starred": bool(record.get("starred")),
        "agent_data_collection_status": True,
        "agent_id": record.get("endpoint_id"),
        "agent_hostname": record.get("host_name"),
        "agent_os_type": _OS_CODES.get(endpoint.os_type, None) if endpoint else None,
        "agent_ip_addresses": list(record.get("host_ip") or []),
        "actor_effective_username": record.get("user_name") or None,
        "mitre_tactic_id_and_name": record.get("mitre_tactic_id_and_name") or None,
        "mitre_technique_id_and_name": record.get("mitre_technique_id_and_name") or None,
        "case_id": record.get("incident_id") or None,
        "events": [{
            "module_id": None, "module_name": None, "association_strength": None,
            "event_type": record.get("event_type"), "event_timestamp": timestamp,
        }],
        "events_length": 1,
    }


def get_alerts(request_data: dict) -> dict:
    """List alerts, by ``filter_data`` or by ``filters``.

    ``filter_data`` is the form this route is documented with by the client
    that uses it -- the XSOAR integration's ``xdr-get-alerts`` -- and answers
    ``{result_count, alerts: [{alert_fields, incident_fields}]}`` (see
    :mod:`utils.xdr_filter_data`). The route read only the public
    ``filters``/``search_from`` form, so the XSOAR command's filter, sort and
    paging were ignored -- every alert came back, unsorted -- and each item's
    ``alert_fields`` was the recorded template, blank: forty alerts with no
    name, no severity and no id.

    The ``filters`` form keeps its answer -- the stored fields, which the
    console reads -- and each item carries its ``alert_fields`` too.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR reply with the matching alerts.
    """
    filter_data = request_data.get("filter_data")
    if filter_data is not None:
        if not isinstance(filter_data, dict):
            msg = "filter_data must be an object"
            raise XdrFilterError(msg)
        rows = [alert_fields(record_dict(a)) for a in xdr_alert_repo.list_all()]
        rows = sort_filter_data(apply_filter_data(rows, filter_data), filter_data)
        page = filter_data_page(rows, filter_data)
        return build_xdr_reply({
            "result_count": len(page),
            "alerts": [{"alert_fields": row, "incident_fields": None} for row in page],
        })

    matched = apply_xdr_filters(
        xdr_alert_repo.list_all(), request_data.get("filters"), _ALERT_FILTER_FIELDS,
    )

    matched = apply_xdr_sort(matched, request_data.get("sort"))

    total = len(matched)
    search_from, search_to = page_bounds(request_data)
    page = [record_dict(r) for r in matched[search_from:search_to]]
    page = [{**r, "alert_fields": alert_fields(r)} for r in page]

    return build_xdr_list_reply(page, total_count=total, key="alerts")


def get_original_alerts(alert_ids: list[str]) -> dict:
    """Return the raw alert each id names, as it was ingested.

    The clue is in the route's name: Cortex answers the *original* alert, and
    its recorded reply carries exactly two members per row — `internal_id`
    and `original_alert_json`, the raw event as a JSON string. mockdr
    answered the parsed alert record instead, wrapped in the paginated
    envelope with a `total_count` and a `result_count` this route has
    neither of. A client reading `original_alert_json` — which is the whole
    point of calling this rather than `get_alerts` — found nothing there.

    Args:
        alert_ids: List of alert identifiers to retrieve.

    Returns:
        XDR reply with one row per alert found.
    """
    rows = []
    for aid in alert_ids:
        alert = xdr_alert_repo.get(aid)
        if not alert:
            continue
        record = record_dict(alert)
        internal = str(record.get("internal_id") or "")
        rows.append({
            "internal_id": int(internal) if internal.isdigit() else internal,
            "original_alert_json": json.dumps(record, default=str),
        })

    return build_xdr_reply({"alerts": rows})


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
    matched = apply_xdr_sort(matched, request_data.get("sort"))

    total = len(matched)
    search_from, search_to = page_bounds(request_data)
    page = [multi_events_alert(record_dict(a)) for a in matched[search_from:search_to]]
    return build_xdr_list_reply(page, total_count=total, key="alerts")
