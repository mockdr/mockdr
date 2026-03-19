"""Cortex XDR Alert command handlers (mutations)."""
from __future__ import annotations

import uuid

from domain.xdr_alert import XdrAlert
from repository.xdr_alert_repo import xdr_alert_repo
from utils.xdr_response import build_xdr_reply


def insert_parsed_alerts(alerts: list[dict]) -> dict:
    """Create alerts from parsed data.

    Args:
        alerts: List of alert dicts to insert.

    Returns:
        XDR reply confirming success.
    """
    now_ms = _epoch_ms()
    for alert_data in alerts:
        alert_id = alert_data.get("alert_id", str(uuid.uuid4()))
        alert = XdrAlert(
            alert_id=alert_id,
            severity=alert_data.get("severity", "medium"),
            name=alert_data.get("product", "External Alert"),
            description=alert_data.get("alert_name", ""),
            source="External",
            detection_timestamp=alert_data.get("timestamp", now_ms),
            host_name=alert_data.get("host_name", ""),
            host_ip=alert_data.get("host_ip", []),
            user_name=alert_data.get("user_name", ""),
            event_type=alert_data.get("event_type", ""),
        )
        xdr_alert_repo.save(alert)

    return build_xdr_reply(True)


def insert_cef_alerts(alerts: list[dict]) -> dict:
    """Create alerts from CEF format data.

    Args:
        alerts: List of alert dicts in CEF format.

    Returns:
        XDR reply confirming success.
    """
    now_ms = _epoch_ms()
    for alert_data in alerts:
        alert_id = str(uuid.uuid4())
        alert = XdrAlert(
            alert_id=alert_id,
            severity=alert_data.get("severity", "medium"),
            name=alert_data.get("name", "CEF Alert"),
            description=alert_data.get("cef_version", ""),
            source="External",
            detection_timestamp=alert_data.get("timestamp", now_ms),
            host_name=alert_data.get("device_host_name", ""),
        )
        xdr_alert_repo.save(alert)

    return build_xdr_reply(True)


def update_alerts(alert_ids: list[str], update_data: dict) -> dict:
    """Update status/severity on one or more alerts.

    Args:
        alert_ids: List of alert identifiers to update.
        update_data: Dict with fields to update (``status``, ``severity``,
            ``starred``, ``comment``).

    Returns:
        XDR reply confirming success.
    """
    allowed = {"severity", "starred", "alert_action_status"}
    # Map common incoming keys to domain fields
    if "status" in update_data:
        update_data["alert_action_status"] = update_data.pop("status")

    for aid in alert_ids:
        alert = xdr_alert_repo.get(aid)
        if alert:
            for key, value in update_data.items():
                if key in allowed and hasattr(alert, key):
                    setattr(alert, key, value)
            xdr_alert_repo.save(alert)

    return build_xdr_reply(True)


def _epoch_ms() -> int:
    """Return current time as epoch milliseconds."""
    from datetime import UTC, datetime
    return int(datetime.now(UTC).timestamp() * 1000)
