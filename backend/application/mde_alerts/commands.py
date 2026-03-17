"""Microsoft Defender for Endpoint Alert command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import asdict

from domain.mde_alert import MdeAlert
from repository.mde_alert_repo import mde_alert_repo
from utils.dt import utc_now


def update_alert(alert_id: str, body: dict) -> dict | None:
    """Update an existing alert (PATCH semantics).

    Supports updating ``status``, ``classification``, ``determination``,
    ``assignedTo``, and appending a ``comment``.

    Args:
        alert_id: GUID of the alert to update.
        body:     Dict with fields to update.

    Returns:
        Updated alert dict, or None if not found.
    """
    alert = mde_alert_repo.get(alert_id)
    if not alert:
        return None

    if "status" in body:
        alert.status = body["status"]
    if "classification" in body:
        alert.classification = body["classification"]
    if "determination" in body:
        alert.determination = body["determination"]
    if "assignedTo" in body:
        alert.assignedTo = body["assignedTo"]
    if "comment" in body:
        alert.comments.append({
            "comment": body["comment"],
            "createdBy": body.get("assignedTo", "analyst@acmecorp.internal"),
            "createdTime": utc_now(),
        })

    now = utc_now()
    alert.lastUpdateTime = now
    if alert.status == "Resolved" and not alert.resolvedTime:
        alert.resolvedTime = now

    mde_alert_repo.save(alert)
    return asdict(alert)


def create_alert_by_reference(body: dict) -> dict:
    """Create a new alert from reference data.

    This endpoint allows creating alerts from custom detection data.

    Args:
        body: Dict with alert creation fields including ``machineId``,
              ``severity``, ``title``, ``description``, ``category``,
              ``eventTime``, and ``reportId``.

    Returns:
        The newly created alert as a dict.
    """
    now = utc_now()
    alert = MdeAlert(
        alertId=str(uuid.uuid4()),
        title=body.get("title", "Custom Alert"),
        description=body.get("description", ""),
        severity=body.get("severity", "Medium"),
        status="New",
        category=body.get("category", "SuspiciousActivity"),
        machineId=body.get("machineId", ""),
        alertCreationTime=now,
        lastUpdateTime=now,
        firstEventTime=body.get("eventTime", now),
        lastEventTime=body.get("eventTime", now),
        detectionSource=body.get("detectionSource", "CustomDetection"),
        threatName=body.get("threatName", ""),
        threatFamilyName=body.get("threatFamilyName", ""),
    )
    mde_alert_repo.save(alert)
    return asdict(alert)


def batch_update_alerts(body: dict) -> list[dict]:
    """Batch update multiple alerts at once.

    Args:
        body: Dict with ``alertIds`` list and fields to update (``status``,
              ``classification``, ``determination``, ``assignedTo``, ``comment``).

    Returns:
        List of updated alert dicts.
    """
    alert_ids: list[str] = body.get("alertIds", [])
    updated: list[dict] = []
    for alert_id in alert_ids:
        result = update_alert(alert_id, body)
        if result:
            updated.append(result)
    return updated
