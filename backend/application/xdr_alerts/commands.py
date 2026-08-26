"""Cortex XDR Alert command handlers (mutations)."""

from __future__ import annotations

import uuid

from application import bridge
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
        # Bridge the alert into Splunk and Sentinel (ADR-009).
        bridge.xdr_alert_changed(alert)

    return build_xdr_reply(True)


_CEF_SEVERITY = {
    range(0, 4): "low",
    range(4, 7): "medium",
    range(7, 9): "high",
    range(9, 11): "critical",
}


def _parse_cef(line: str) -> dict:
    """The fields of one CEF line: header pipes, then key=value extensions."""
    parts = line.split("|", 7)
    if len(parts) < 7 or not parts[0].startswith("CEF:"):
        return {"name": "CEF Alert", "cef_version": line[:64]}
    severity = "medium"
    if parts[6].strip().isdigit():
        level = int(parts[6].strip())
        severity = next((name for band, name in _CEF_SEVERITY.items() if level in band), "medium")
    extension = dict(
        pair.split("=", 1) for pair in (parts[7] if len(parts) > 7 else "").split() if "=" in pair
    )
    return {
        "name": parts[5].strip() or "CEF Alert",
        "severity": severity,
        "cef_version": f"{parts[1]} {parts[2]} {parts[3]}".strip(),
        "device_host_name": extension.get("dvchost") or extension.get("shost") or "",
    }


def insert_cef_alerts(alerts: list[dict]) -> dict:
    """Create alerts from CEF format data.

    Args:
        alerts: List of alert dicts in CEF format.

    Returns:
        XDR reply confirming success.
    """
    now_ms = _epoch_ms()
    for raw in alerts:
        # The real API takes CEF *lines* ("CEF:0|Vendor|Product|…"); a dict
        # is accepted too. A string used to crash this with AttributeError.
        alert_data = _parse_cef(raw) if isinstance(raw, str) else raw
        if not isinstance(alert_data, dict):
            continue
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
        # Bridge the alert into Splunk and Sentinel (ADR-009).
        bridge.xdr_alert_changed(alert)

    return build_xdr_reply(True)


def _epoch_ms() -> int:
    """Return current time as epoch milliseconds."""
    from datetime import UTC, datetime

    return int(datetime.now(UTC).timestamp() * 1000)
