"""Microsoft Defender for Endpoint Alert command handlers (mutations)."""
from __future__ import annotations

import time
import uuid

from application import bridge
from domain.event_bus import MdeAlertCreated, event_bus
from domain.mde_alert import MdeAlert
from repository.mde_alert_repo import mde_alert_repo
from utils.dt import utc_now
from utils.mde_fixtures import complete_mde
from utils.mde_serde import to_mde_resource
from utils.serde import record_dict


class InvalidAlertUpdateError(ValueError):
    """An alert update Defender refuses with ``400``."""

    def __init__(self, code: str, message: str) -> None:
        """Keep the Defender error code beside the message."""
        super().__init__(message)
        self.code = code


#: What an update may set, from update-alert and batch-update-alerts on
#: https://learn.microsoft.com/en-us/defender-endpoint/api/. ``Unknown`` is a
#: status the alert resource can carry but no update lists. The two pages
#: name three determinations differently -- ``ConfirmedActivity`` /
#: ``ConfirmedUserActivity``, ``NotMalicious`` / ``Clean`` -- and both
#: spellings are taken rather than refuse one the docs print.
UPDATABLE: dict[str, frozenset[str]] = {
    "status": frozenset({"New", "InProgress", "Resolved"}),
    "classification": frozenset({"TruePositive", "InformationalExpectedActivity", "FalsePositive"}),
    "determination": frozenset({
        "MultiStagedAttack", "MaliciousUserActivity", "CompromisedUser", "Malware", "Phishing",
        "UnwantedSoftware", "Other", "SecurityTesting", "LineOfBusinessApplication",
        "ConfirmedActivity", "ConfirmedUserActivity", "NotMalicious", "Clean",
        "InsufficientData",
    }),
}


def validate_alert_update(body: dict) -> None:
    """Refuse a value the update pages do not list.

    The mock stored ``status``, ``classification`` and ``determination``
    verbatim, so ``"status": "Closed"`` -- a Sentinel word -- came back as the
    alert's status with a 200, and every later read carried a value no
    Defender client can map.

    Raises:
        InvalidAlertUpdateError: ``InvalidRequestBody``.
    """
    for field, allowed in UPDATABLE.items():
        if field in body and body[field] is not None and body[field] not in allowed:
            raise InvalidAlertUpdateError(
                "InvalidRequestBody",
                f"Invalid request body. {field} '{body[field]}' is not one of "
                f"{', '.join(sorted(allowed))}.",
            )


def update_alert(alert_id: str, body: dict) -> dict | None:
    """Update an existing alert (PATCH semantics).

    Supports updating ``status``, ``classification``, ``determination``,
    ``assignedTo``, and appending a ``comment``.

    Args:
        alert_id: GUID of the alert to update.
        body:     Dict with fields to update.

    Returns:
        Updated alert dict, or None if not found.

    Raises:
        InvalidAlertUpdateError: A value the update page does not list.
    """
    validate_alert_update(body)
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
    bridge.mde_alert_changed(alert)
    return complete_mde(to_mde_resource(record_dict(alert), "alertId"), "alert")


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

    # Bridge the alert into Splunk and Sentinel (ADR-009).
    payload = to_mde_resource(record_dict(alert), "alertId")
    event_bus.publish(MdeAlertCreated(
        entity_id=alert.alertId,
        payload=payload,
        timestamp=time.time(),
    ))
    return payload


def batch_update_alerts(body: dict) -> None:
    """Batch update multiple alerts at once.

    ``alertIds`` is "Required" (batch-update-alerts); the mock defaulted it to
    an empty list and answered 200 having changed nothing. The values are
    checked once, before any alert changes, so a refused batch leaves every
    alert as it was.

    Args:
        body: Dict with ``alertIds`` list and fields to update (``status``,
              ``classification``, ``determination``, ``assignedTo``, ``comment``).

    Raises:
        InvalidAlertUpdateError: ``MissingRequiredParameter`` without
            ``alertIds``, ``InvalidRequestBody`` for a value not listed.
    """
    alert_ids = body.get("alertIds")
    if not isinstance(alert_ids, list) or not alert_ids:
        raise InvalidAlertUpdateError("MissingRequiredParameter", "Parameter alertIds is missing.")
    validate_alert_update(body)
    for alert_id in alert_ids:
        update_alert(str(alert_id), body)
