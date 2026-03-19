"""Microsoft Graph Intune Enrollment / Update Rings / Device Categories endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_feature
from application.graph.enrollment import queries as enrollment_queries

router = APIRouter(tags=["Graph Enrollment"])


@router.get("/beta/deviceManagement/windowsUpdateForBusinessConfigurations")
async def list_update_rings(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Windows Update for Business configurations (update rings)."""
    return enrollment_queries.list_update_rings(top=top, skip=skip)


@router.get("/v1.0/deviceManagement/deviceEnrollmentConfigurations")
async def list_enrollment_restrictions(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune device enrollment configurations."""
    return enrollment_queries.list_enrollment_restrictions(top=top, skip=skip)


@router.get("/v1.0/deviceManagement/deviceCategories")
async def list_device_categories(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune device categories."""
    return enrollment_queries.list_device_categories(top=top, skip=skip)
