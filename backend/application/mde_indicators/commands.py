"""Microsoft Defender for Endpoint Indicator command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import asdict

from domain.mde_indicator import MdeIndicator
from repository.mde_indicator_repo import mde_indicator_repo
from utils.dt import utc_now


def create_indicator(body: dict) -> dict:
    """Create a new threat indicator.

    Args:
        body: Dict with indicator fields including ``indicatorValue``,
              ``indicatorType``, ``action``, ``title``, ``description``,
              ``severity``, and optional ``expirationTime``.

    Returns:
        The newly created indicator as a dict.
    """
    now = utc_now()
    indicator = MdeIndicator(
        indicatorId=str(uuid.uuid4()),
        indicatorValue=body.get("indicatorValue", ""),
        indicatorType=body.get("indicatorType", ""),
        action=body.get("action", "Alert"),
        severity=body.get("severity", "Medium"),
        title=body.get("title", ""),
        description=body.get("description", ""),
        recommendedActions=body.get("recommendedActions", ""),
        rbacGroupNames=body.get("rbacGroupNames", []),
        generateAlert=body.get("generateAlert", True),
        createdBy=body.get("createdBy", "analyst@acmecorp.internal"),
        createdByDisplayName=body.get("createdByDisplayName", ""),
        createdBySource=body.get("createdBySource", "User"),
        creationTimeDateTimeUtc=now,
        expirationTime=body.get("expirationTime", ""),
        lastUpdatedBy=body.get("createdBy", "analyst@acmecorp.internal"),
        lastUpdateTime=now,
    )
    mde_indicator_repo.save(indicator)
    return asdict(indicator)


def update_indicator(indicator_id: str, body: dict) -> dict | None:
    """Update an existing indicator (PATCH semantics).

    Args:
        indicator_id: GUID of the indicator to update.
        body:         Dict with fields to update.

    Returns:
        Updated indicator dict, or None if not found.
    """
    indicator = mde_indicator_repo.get(indicator_id)
    if not indicator:
        return None

    if "action" in body:
        indicator.action = body["action"]
    if "severity" in body:
        indicator.severity = body["severity"]
    if "title" in body:
        indicator.title = body["title"]
    if "description" in body:
        indicator.description = body["description"]
    if "expirationTime" in body:
        indicator.expirationTime = body["expirationTime"]
    if "recommendedActions" in body:
        indicator.recommendedActions = body["recommendedActions"]
    if "rbacGroupNames" in body:
        indicator.rbacGroupNames = body["rbacGroupNames"]
    if "generateAlert" in body:
        indicator.generateAlert = body["generateAlert"]

    indicator.lastUpdatedBy = body.get("updatedBy", "analyst@acmecorp.internal")
    indicator.lastUpdateTime = utc_now()

    mde_indicator_repo.save(indicator)
    return asdict(indicator)


def delete_indicator(indicator_id: str) -> bool:
    """Delete an indicator by its ID.

    Args:
        indicator_id: GUID of the indicator to delete.

    Returns:
        True if the indicator was deleted, False if not found.
    """
    return mde_indicator_repo.delete(indicator_id)


def batch_update_indicators(body: dict) -> dict:
    """Batch delete indicators by their values.

    MDE batch update supports deleting indicators by ``indicatorValue``.

    Args:
        body: Dict with ``indicatorValues`` list of indicator values to delete.

    Returns:
        Summary dict with count of deleted indicators.
    """
    indicator_values: list[str] = body.get("indicatorValues", [])
    deleted_count = 0
    all_indicators = mde_indicator_repo.list_all()
    for indicator in all_indicators:
        if indicator.indicatorValue in indicator_values:
            mde_indicator_repo.delete(indicator.indicatorId)
            deleted_count += 1
    return {"value": deleted_count}
