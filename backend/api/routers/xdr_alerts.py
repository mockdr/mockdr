"""Cortex XDR Alerts API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_alerts import commands as alert_commands
from application.xdr_alerts import queries as alert_queries

router = APIRouter(tags=["XDR Alerts"])


@router.post("/alerts/get_alerts_by_filter_data/")
def get_alerts(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Filter alerts by severity, source, creation_time, with pagination."""
    request_data = body.get("request_data", {})
    return alert_queries.get_alerts(request_data)


@router.post("/alerts/get_original_alerts/")
def get_original_alerts(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get full alert data for specific alert IDs."""
    request_data = body.get("request_data", {})
    alert_ids = request_data.get("alert_id_list", [])
    return alert_queries.get_original_alerts(alert_ids)


@router.post("/alerts/insert_parsed_alerts/")
def insert_parsed_alerts(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Insert alerts from parsed data."""
    request_data = body.get("request_data", {})
    alerts = request_data.get("alerts", [])
    return alert_commands.insert_parsed_alerts(alerts)


@router.post("/alerts/insert_cef_alerts/")
def insert_cef_alerts(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Insert alerts from CEF format data."""
    request_data = body.get("request_data", {})
    alerts = request_data.get("alerts", [])
    return alert_commands.insert_cef_alerts(alerts)


@router.post("/alerts/update_alerts")
def update_alerts(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Update status/severity on one or more alerts."""
    request_data = body.get("request_data", {})
    alert_ids = request_data.get("alert_id_list", [])
    update_data = request_data.get("update_data", {})
    return alert_commands.update_alerts(alert_ids, update_data)
