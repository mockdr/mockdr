"""Cortex XDR Incidents API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_incidents import commands as incident_commands
from application.xdr_incidents import queries as incident_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR Incidents"])


@router.post("/incidents/get_incidents/")
def get_incidents(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List incidents with optional filtering and pagination."""
    request_data = body.get("request_data", {})
    return incident_queries.get_incidents(request_data)


@router.post("/incidents/get_incident_extra_data/")
def get_incident_extra_data(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get incident details with linked alerts and network artifacts."""
    request_data = body.get("request_data", {})
    incident_id = request_data.get("incident_id", "")
    result = incident_queries.get_incident_extra_data(incident_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Incident {incident_id} not found"),
        )
    return result


@router.post("/incidents/update_incident/")
def update_incident(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Update an incident's status, severity, assignee, or manual_score."""
    request_data = body.get("request_data", {})
    incident_id = request_data.get("incident_id", "")
    update_data = request_data.get("update_data", {})
    result = incident_commands.update_incident(incident_id, update_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Incident {incident_id} not found"),
        )
    return result
