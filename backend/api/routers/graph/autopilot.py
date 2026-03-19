"""Microsoft Graph Windows Autopilot endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_feature
from application.graph.autopilot import queries as autopilot_queries

router = APIRouter(tags=["Graph Autopilot"])


@router.get("/v1.0/deviceManagement/windowsAutopilotDeviceIdentities")
async def list_autopilot_devices(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Windows Autopilot device identities."""
    return autopilot_queries.list_autopilot_devices(top=top, skip=skip)


@router.get("/beta/deviceManagement/windowsAutopilotDeploymentProfiles")
async def list_autopilot_profiles(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Windows Autopilot deployment profiles."""
    return autopilot_queries.list_autopilot_profiles(top=top, skip=skip)
