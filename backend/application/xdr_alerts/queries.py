"""Cortex XDR Alert query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_alert_repo import xdr_alert_repo
from utils.xdr_response import build_xdr_list_reply


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

    filters = request_data.get("filters", [])
    for f in filters:
        field = f.get("field", "")
        value = f.get("value")
        if field == "severity" and value:
            values = value if isinstance(value, list) else [value]
            all_alerts = [a for a in all_alerts if a["severity"] in values]
        elif field == "alert_source" and value:
            values = value if isinstance(value, list) else [value]
            all_alerts = [a for a in all_alerts if a["source"] in values]
        elif field == "creation_time":
            gte = f.get("gte")
            lte = f.get("lte")
            if gte is not None:
                all_alerts = [a for a in all_alerts if a["detection_timestamp"] >= gte]
            if lte is not None:
                all_alerts = [a for a in all_alerts if a["detection_timestamp"] <= lte]

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
