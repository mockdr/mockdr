"""Microsoft Defender for Endpoint Alerts API router.

Implements MDE alert endpoints: listing, detail, update (PATCH),
create by reference, and batch update.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response

from api.mde_auth import require_mde_auth, require_mde_write
from application.mde_alerts import commands as alert_commands
from application.mde_alerts import queries as alert_queries
from utils.mde_filterable import refuse_unfilterable
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Alerts"])


@router.get("/api/alerts")
def list_alerts(
    filter_str: str = Query(None, alias="$filter"),
    # "$top with max value of 10,000" (get-alerts on learn.microsoft.com/en-us/
    # defender-endpoint/api/); the cap was 1000. No default page size is
    # documented, so the default stays 50.
    top: int = Query(50, alias="$top", ge=1, le=10000),
    skip: int = Query(0, alias="$skip", ge=0),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    count: bool = Query(False, alias="$count"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all alerts with optional OData query parameters."""
    refuse_unfilterable(filter_str, "alerts")
    return alert_queries.list_alerts(filter_str, top, skip, orderby, select, count)


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
            detail=build_mde_error_response("ResourceNotFound", f"Alert {alert_id} not found"),
        )
    return result


@router.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Update an alert (status, classification, determination, assignedTo, comment)."""
    try:
        result = alert_commands.update_alert(alert_id, body)
    except alert_commands.InvalidAlertUpdateError as exc:
        raise HTTPException(
            status_code=400, detail=build_mde_error_response(exc.code, str(exc)),
        ) from exc
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("ResourceNotFound", f"Alert {alert_id} not found"),
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
) -> Response:
    """Batch update multiple alerts at once.

    "If successful, this method returns 200 OK, with an empty response body"
    (https://learn.microsoft.com/en-us/defender-endpoint/api/batch-update-alerts).
    The mock answered an OData collection of the updated alerts, which a
    client written against it would go on to read and never find in
    production.
    """
    try:
        alert_commands.batch_update_alerts(body)
    except alert_commands.InvalidAlertUpdateError as exc:
        raise HTTPException(
            status_code=400, detail=build_mde_error_response(exc.code, str(exc)),
        ) from exc
    return Response(status_code=200)
