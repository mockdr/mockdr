"""Microsoft Defender for Endpoint Alerts API router.

Implements MDE alert endpoints: listing, detail, update (PATCH),
create by reference, and batch update.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth, require_mde_write
from application.mde_alerts import commands as alert_commands
from application.mde_alerts import queries as alert_queries
from utils.mde_response import build_mde_error_response, build_mde_list_response

router = APIRouter(tags=["MDE Alerts"])


@router.get("/api/alerts")
def list_alerts(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all alerts with optional OData query parameters."""
    return alert_queries.list_alerts(filter_str, top, skip, orderby, select)


@router.get("/api/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single alert by its alert ID."""
    result = alert_queries.get_alert(alert_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Alert {alert_id} not found"),
        )
    return result


@router.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Update an alert (status, classification, determination, assignedTo, comment)."""
    result = alert_commands.update_alert(alert_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Alert {alert_id} not found"),
        )
    return result


@router.post("/api/alerts/createAlertByReference")
def create_alert_by_reference(
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Create a new alert from reference data."""
    return alert_commands.create_alert_by_reference(body)


@router.post("/api/alerts/batchUpdate")
def batch_update_alerts(
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Batch update multiple alerts at once."""
    updated = alert_commands.batch_update_alerts(body)
    return build_mde_list_response(updated)
